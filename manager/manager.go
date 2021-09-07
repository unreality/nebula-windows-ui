package manager

import (
	"errors"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"golang.zx2c4.com/wireguard/windows/elevate"
	"golang.zx2c4.com/wireguard/windows/ringlogger"
	"golang.zx2c4.com/wireguard/windows/services"
	"log"
	"os"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var serviceName = "NebulaManagerService"

func makeInheritableAndGetStr(f *os.File) (str string, err error) {
	sc, err := f.SyscallConn()
	if err != nil {
		return
	}
	err2 := sc.Control(func(fd uintptr) {
		err = windows.SetHandleInformation(windows.Handle(fd), windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT)
		str = strconv.FormatUint(uint64(fd), 10)
	})
	if err2 != nil {
		err = err2
	}
	return
}

func InstallManagerService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	path, err := os.Executable()
	if err != nil {
		return nil
	}

	service, err := m.OpenService(serviceName)
	if err == nil {
		status, err := service.Query()
		if err != nil {
			service.Close()
			return err
		}
		if status.State != svc.Stopped {
			service.Close()
			if status.State == svc.StartPending {

				return nil
			}
			return errors.New("Manager already installed and running")
		}
		err = service.Delete()
		service.Close()
		if err != nil {
			return err
		}
		for {
			service, err = m.OpenService(serviceName)
			if err != nil {
				break
			}
			service.Close()
			time.Sleep(time.Second / 3)
		}
	}

	config := mgr.Config{
		ServiceType:  windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:    mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
		DisplayName:  "Nebula Manager Service",
	}

	service, err = m.CreateService(serviceName, path, config, "-manager")
	if err != nil {
		return err
	}
	service.Start()
	return service.Close()
}

func UninstallManagerService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}

	service, err := m.OpenService(serviceName)
	if err != nil {
		return err
	}
	service.Control(svc.Stop)
	err = service.Delete()
	err2 := service.Close()
	if err != nil {
		return err
	}
	return err2
}

type managerService struct{}

func (service *managerService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (svcSpecificEC bool, exitCode uint32) {
	changes <- svc.Status{State: svc.StartPending}

	var err error
	serviceError := services.ErrorSuccess

	defer func() {
		svcSpecificEC, exitCode = services.DetermineErrorCode(err, serviceError)
		logErr := services.CombineErrors(err, serviceError)
		if logErr != nil {
			log.Print(logErr)
		}
		changes <- svc.Status{State: svc.StopPending}
	}()

	var ringLogFile string = "C:\\Temp\\mgr.log"

	//ringLogFile, err = conf.LogFile(true)
	//if err != nil {
	//    serviceError = services.ErrorRingloggerOpen
	//    return
	//}

	err = ringlogger.InitGlobalLogger(ringLogFile, "MGR")
	if err != nil {
		serviceError = services.ErrorRingloggerOpen
		return
	}

	log.Println("Starting")

	path, err := os.Executable()
	if err != nil {
		serviceError = services.ErrorDetermineExecutablePath
		return
	}

	procs := make(map[uint32]*os.Process)
	aliveSessions := make(map[uint32]bool)
	procsLock := sync.Mutex{}
	stoppingManager := false
	//operatorGroupSid, _ := windows.CreateWellKnownSid(windows.WinBuiltinNetworkConfigurationOperatorsSid)

	startProcess := func(session uint32) {
		defer func() {
			runtime.UnlockOSThread()
			procsLock.Lock()
			delete(aliveSessions, session)
			procsLock.Unlock()
		}()

		var userToken windows.Token
		err := windows.WTSQueryUserToken(session, &userToken)
		if err != nil {
			return
		}
		isAdmin := elevate.TokenIsElevatedOrElevatable(userToken)
		isOperator := false
		//if !isAdmin && conf.AdminBool("LimitedOperatorUI") && operatorGroupSid != nil {
		//    linkedToken, err := userToken.GetLinkedToken()
		//    var impersonationToken windows.Token
		//    if err == nil {
		//        err = windows.DuplicateTokenEx(linkedToken, windows.TOKEN_QUERY, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &impersonationToken)
		//        linkedToken.Close()
		//    } else {
		//        err = windows.DuplicateTokenEx(userToken, windows.TOKEN_QUERY, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &impersonationToken)
		//    }
		//    if err == nil {
		//        isOperator, err = impersonationToken.IsMember(operatorGroupSid)
		//        isOperator = isOperator && err == nil
		//        impersonationToken.Close()
		//    }
		//}
		if !isAdmin && !isOperator {
			userToken.Close()
			return
		}
		user, err := userToken.GetTokenUser()
		if err != nil {
			log.Printf("Unable to lookup user from token: %v", err)
			userToken.Close()
			return
		}
		username, domain, accType, err := user.User.Sid.LookupAccount("")
		if err != nil {
			log.Printf("Unable to lookup username from sid: %v", err)
			userToken.Close()
			return
		}
		if accType != windows.SidTypeUser {
			userToken.Close()
			return
		}
		userProfileDirectory, _ := userToken.GetUserProfileDirectory()
		var elevatedToken, runToken windows.Token
		if isAdmin {
			if userToken.IsElevated() {
				elevatedToken = userToken
			} else {
				elevatedToken, err = userToken.GetLinkedToken()
				userToken.Close()
				if err != nil {
					log.Printf("Unable to elevate token: %v", err)
					return
				}
				if !elevatedToken.IsElevated() {
					elevatedToken.Close()
					log.Println("Linked token is not elevated")
					return
				}
			}
			runToken = elevatedToken
		} else {
			runToken = userToken
		}
		defer runToken.Close()
		userToken = 0
		first := true
		for {
			if stoppingManager {
				return
			}

			procsLock.Lock()
			if alive := aliveSessions[session]; !alive {
				procsLock.Unlock()
				return
			}
			procsLock.Unlock()

			if !first {
				time.Sleep(time.Second)
			} else {
				first = false
			}

			ourReader, theirWriter, err := os.Pipe()
			if err != nil {
				log.Printf("Unable to create pipe: %v", err)
				return
			}
			theirReader, ourWriter, err := os.Pipe()
			if err != nil {
				log.Printf("Unable to create pipe: %v", err)
				return
			}
			theirEvents, ourEvents, err := os.Pipe()
			if err != nil {
				log.Printf("Unable to create pipe: %v", err)
				return
			}

			IPCServerListen(ourReader, ourWriter, ourEvents, elevatedToken)

			theirLogMapping, err := ringlogger.Global.ExportInheritableMappingHandle()
			if err != nil {
				log.Printf("Unable to export inheritable mapping handle for logging: %v", err)
				return
			}

			theirReaderStr, err := makeInheritableAndGetStr(theirReader)
			theirWriterStr, err := makeInheritableAndGetStr(theirWriter)
			theirEventStr, err := makeInheritableAndGetStr(theirEvents)
			theirLogMappingStr := strconv.FormatUint(uint64(theirLogMapping), 10)

			log.Printf("Starting UI process for user ‘%s@%s’ for session %d", username, domain, session)

			devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
			if err != nil {
				log.Printf("Could not open NUL file")
				return
			}

			attr := &os.ProcAttr{
				Sys: &syscall.SysProcAttr{
					Token: syscall.Token(elevatedToken),
				},
				Files: []*os.File{devNull, devNull, devNull},
				Dir:   userProfileDirectory,
			}
			procsLock.Lock()
			var proc *os.Process
			if alive := aliveSessions[session]; alive {
				proc, err = os.StartProcess(path, []string{path, "-ui", theirReaderStr, theirWriterStr, theirEventStr, theirLogMappingStr}, attr)
			} else {
				err = errors.New("Session has logged out")
			}

			//procsLock.Lock()
			//var proc *uiProcess
			//if alive := aliveSessions[session]; alive {
			//    proc, err = launchUIProcess(path, []string{
			//        path,
			//        "-ui",
			//        strconv.FormatUint(uint64(theirReader.Fd()), 10),
			//        strconv.FormatUint(uint64(theirWriter.Fd()), 10),
			//        strconv.FormatUint(uint64(theirEvents.Fd()), 10),
			//        strconv.FormatUint(uint64(theirLogMapping), 10),
			//    }, userProfileDirectory, []windows.Handle{
			//        windows.Handle(theirReader.Fd()),
			//        windows.Handle(theirWriter.Fd()),
			//        windows.Handle(theirEvents.Fd()),
			//        theirLogMapping}, runToken)
			//} else {
			//    err = errors.New("Session has logged out")
			//}
			procsLock.Unlock()
			theirReader.Close()
			theirWriter.Close()
			theirEvents.Close()
			windows.CloseHandle(theirLogMapping)
			if err != nil {
				ourReader.Close()
				ourWriter.Close()
				ourEvents.Close()
				log.Printf("Unable to start manager UI process for user '%s@%s' for session %d: %v", username, domain, session, err)
				return
			}

			procsLock.Lock()
			procs[session] = proc
			procsLock.Unlock()

			sessionIsDead := false
			processStatus, err := proc.Wait()
			if err == nil {
				exitCode := processStatus.Sys().(syscall.WaitStatus).ExitCode
				log.Printf("Exited UI process for user '%s@%s' for session %d with status %x", username, domain, session, exitCode)
				const STATUS_DLL_INIT_FAILED_LOGOFF = 0xC000026B
				sessionIsDead = exitCode == STATUS_DLL_INIT_FAILED_LOGOFF
			} else {
				log.Printf("Unable to wait for UI process for user '%s@%s' for session %d: %v", username, domain, session, err)
			}

			procsLock.Lock()
			delete(procs, session)
			procsLock.Unlock()
			ourReader.Close()
			ourWriter.Close()
			ourEvents.Close()

			if sessionIsDead {
				return
			}
		}
	}
	procsGroup := sync.WaitGroup{}
	goStartProcess := func(session uint32) {
		procsGroup.Add(1)
		go func() {
			startProcess(session)
			procsGroup.Done()
		}()
	}

	var sessionsPointer *windows.WTS_SESSION_INFO
	var count uint32
	err = windows.WTSEnumerateSessions(0, 0, 1, &sessionsPointer, &count)
	if err != nil {
		serviceError = services.ErrorEnumerateSessions
		return
	}
	sessions := *(*[]windows.WTS_SESSION_INFO)(unsafe.Pointer(&struct {
		addr *windows.WTS_SESSION_INFO
		len  int
		cap  int
	}{sessionsPointer, int(count), int(count)}))
	for _, session := range sessions {
		if session.State != windows.WTSActive && session.State != windows.WTSDisconnected {
			continue
		}
		procsLock.Lock()
		if alive := aliveSessions[session.SessionID]; !alive {
			aliveSessions[session.SessionID] = true
			if _, ok := procs[session.SessionID]; !ok {
				goStartProcess(session.SessionID)
			}
		}
		procsLock.Unlock()
	}
	windows.WTSFreeMemory(uintptr(unsafe.Pointer(sessionsPointer)))

	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptSessionChange}

	uninstall := false
loop:
	for {
		select {
		case <-quitManagersChan:
			uninstall = true
			break loop
		case c := <-r:
			switch c.Cmd {
			case svc.Stop:
				break loop
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.SessionChange:
				if c.EventType != windows.WTS_SESSION_LOGON && c.EventType != windows.WTS_SESSION_LOGOFF {
					continue
				}
				sessionNotification := (*windows.WTSSESSION_NOTIFICATION)(unsafe.Pointer(c.EventData))
				if uintptr(sessionNotification.Size) != unsafe.Sizeof(*sessionNotification) {
					log.Printf("Unexpected size of WTSSESSION_NOTIFICATION: %d", sessionNotification.Size)
					continue
				}
				if c.EventType == windows.WTS_SESSION_LOGOFF {
					procsLock.Lock()
					delete(aliveSessions, sessionNotification.SessionID)
					if proc, ok := procs[sessionNotification.SessionID]; ok {
						proc.Kill()
					}
					procsLock.Unlock()
				} else if c.EventType == windows.WTS_SESSION_LOGON {
					procsLock.Lock()
					if alive := aliveSessions[sessionNotification.SessionID]; !alive {
						aliveSessions[sessionNotification.SessionID] = true
						if _, ok := procs[sessionNotification.SessionID]; !ok {
							goStartProcess(sessionNotification.SessionID)
						}
					}
					procsLock.Unlock()
				}

			default:
				log.Printf("Unexpected service control request #%d", c)
			}
		}
	}

	changes <- svc.Status{State: svc.StopPending}
	procsLock.Lock()
	stoppingManager = true

	//IPCServerNotifyManagerStopping()

	for _, proc := range procs {
		proc.Kill()
	}
	procsLock.Unlock()
	procsGroup.Wait()
	if uninstall {
		err = UninstallManagerService()
		if err != nil {
			log.Printf("Unable to uninstall manager when quitting: %v", err)
		}
	}
	return
}

func RunService() error {
	return svc.Run(serviceName, &managerService{})
}
