package main

import (
	"fmt"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/elevate"
	"log"
	"nebula-windows-ui/manager"
	"nebula-windows-ui/ui"
	"os"
	"path/filepath"
	"strconv"
)

func fatal(v ...interface{}) {
	windows.MessageBox(0, windows.StringToUTF16Ptr(fmt.Sprint(v...)), windows.StringToUTF16Ptr(fmt.Sprintf("Error")), windows.MB_ICONERROR)
	os.Exit(1)
}

func fatalf(format string, v ...interface{}) {
	fatal(fmt.Sprintf(format, v...))
}

func checkForAdminGroup() {
	// This is not a security check, but rather a user-confusion one.
	var processToken windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, &processToken)
	if err != nil {
		fatalf("Unable to open current process token: %v", err)
	}
	defer processToken.Close()
	if !elevate.TokenIsElevatedOrElevatable(processToken) {
		fatalf("Nebula may only be used by users who are a member of the Builtin %s group.", elevate.AdminGroupName())
	}
}

func execElevatedManagerServiceInstaller() error {
	path, err := os.Executable()
	if err != nil {
		return err
	}

	err = elevate.ShellExecute(path, "-startmanager", "", windows.SW_SHOW)
	if err != nil && err != windows.ERROR_CANCELLED {
		return err
	}
	os.Exit(0)
	return windows.ERROR_UNHANDLED_EXCEPTION // Not reached
}

func pipeFromHandleArgument(handleStr string) (*os.File, error) {
	handleInt, err := strconv.ParseUint(handleStr, 10, 64)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handleInt), "pipe"), nil
}

func main() {

	if len(os.Args) <= 1 {
		checkForAdminGroup()
		err := execElevatedManagerServiceInstaller()
		if err != nil {
			fatal(err)
		}
		return
	}
	switch os.Args[1] {
	case "-ui":

		if len(os.Args) <= 5 {
			fmt.Printf("-ui missing arguments")
			return
		}

		f, err := os.OpenFile(fmt.Sprintf("C:\\Temp\\ui-log.log"), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			fmt.Printf("error opening file: %v", err)
			return
		}
		defer f.Close()

		log.SetOutput(f)
		log.SetPrefix("[GUI] ")

		var processToken windows.Token
		isAdmin := false
		err = windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, &processToken)
		if err == nil {
			isAdmin = elevate.TokenIsElevatedOrElevatable(processToken)
			processToken.Close()
		}
		if isAdmin {
			err := elevate.DropAllPrivileges(false)
			if err != nil {
				fatal(err)
			}
		}
		readPipe, err := pipeFromHandleArgument(os.Args[2])
		if err != nil {
			fatal(err)
		}
		writePipe, err := pipeFromHandleArgument(os.Args[3])
		if err != nil {
			fatal(err)
		}
		eventPipe, err := pipeFromHandleArgument(os.Args[4])
		if err != nil {
			fatal(err)
		}

		//ringlogger.Global, err = ringlogger.NewRingloggerFromInheritedMappingHandle(os.Args[5], "GUI")
		//if err != nil {
		//    fatal(err)
		//}

		manager.InitializeIPCClient(readPipe, writePipe, eventPipe)
		//ui.IsAdmin = isAdmin
		ui.RunUI()
		return

	case "-manager":
		err := manager.RunService()
		if err != nil {
			fatal(err)
		}
		return
	case "-startmanager":

		err := manager.InstallManagerService()
		if err != nil {
			fatal(err)
		}
		return
	case "-stopmanager":

		err := manager.UninstallManagerService()
		if err != nil {
			fatal(err)
		}
		return
	case "-tunnel":
		if len(os.Args) <= 2 {
			fmt.Printf("-tunnel needs config path")
			return
		}

		tunnelName := filepath.Base(os.Args[2])
		manager.RunTunnelService(tunnelName, os.Args[2])

		os.Exit(0)
	case "-rmtunnel":
		if len(os.Args) <= 2 {
			fmt.Printf("-rmtunnel needs config path")
			return
		}

		tunnelName := filepath.Base(os.Args[2])
		manager.UninstallTunnelService(tunnelName)

		os.Exit(0)
	}

}
