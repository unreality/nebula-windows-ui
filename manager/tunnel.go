package manager

import (
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"golang.zx2c4.com/wireguard/windows/services"
	"log"
	"os"
	"time"
	"unsafe"
)

type tunnelService struct {
	configPath string
}

func InstallTunnelService(tunnelName string, configPath string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	path, err := os.Executable()
	if err != nil {
		return nil
	}

	serviceName := fmt.Sprintf("Nebula_%s", tunnelName)

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
			return errors.New("Tunnel with specified name already installed and running")
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
		DisplayName:  fmt.Sprintf("Nebula Tunnel %s", tunnelName),
	}

	service, err = m.CreateService(serviceName, path, config, "-tunnel", configPath)
	if err != nil {
		return err
	}
	service.Start()
	return service.Close()
}

func UninstallTunnelService(tunnelName string) error {
	serviceName := fmt.Sprintf("Nebula_%s", tunnelName)

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

func (service *tunnelService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (svcSpecificEC bool, exitCode uint32) {
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

	//launch nebula tunnel

	f, err := os.OpenFile(fmt.Sprintf("%s\\tunnel.log", service.configPath), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Printf("error opening file: %v", err)
		return
	}
	defer f.Close()

	l := logrus.New()
	l.Out = f

	err = os.Chdir(service.configPath)
	if err != nil {
		l.Printf("failed to change working directory to %s -- %s. Config may be broken\n", service.configPath, err)
		return
	}

	config := nebula.NewConfig(l)
	l.Printf("Attempting to load %s\n", service.configPath)
	err = config.Load(service.configPath)
	if err != nil {
		l.Printf("failed to load config: %s\n", err)
		return
	}

	nebulaTun, err := nebula.Main(config, false, "0.1", l, nil)
	if err != nil {
		l.Printf("failed to start tunnel: %s\n", err)
		return
	}

	go nebulaTun.Start()

	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptSessionChange}

loop:
	for {
		select {
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
					//stop tunnel
					nebulaTun.Stop()
				} else if c.EventType == windows.WTS_SESSION_LOGON {
					//start tunnel
					nebulaTun.Start()
				}

			default:
				log.Printf("Unexpected service control request #%d", c)
			}
		}
	}

	changes <- svc.Status{State: svc.StopPending}
	nebulaTun.Stop()

	return
}

func RunTunnelService(tunnelName string, configPath string) error {
	serviceName := fmt.Sprintf("Nebula_%s", tunnelName)
	return svc.Run(serviceName, &tunnelService{
		configPath: configPath,
	})
}
