package ui

import (
	"fmt"
	"github.com/getlantern/systray"
	"golang.org/x/sys/windows"
	"log"
	"nebula-windows-ui/manager"
	"os"
	"path/filepath"
)

func ShowError(heading string, msg string) {
	windows.MessageBox(0, windows.StringToUTF16Ptr(msg), windows.StringToUTF16Ptr(heading), windows.MB_ICONERROR)
}

func ToggleTunnel(selectedTunnel *manager.Tunnel) error {
	if selectedTunnel.State == manager.TunnelStarted {
		selectedTunnel.State = manager.TunnelStopping
		log.Printf("Deactivating %s\n", selectedTunnel.Name)
		err := manager.IPCClientStopTunnel(selectedTunnel.Name)
		if err != nil {
			ShowError("Error deactivating tunnel", fmt.Sprintf("%s", err))
			return err
		}
		selectedTunnel.State = manager.TunnelStopped
	} else {

		log.Printf("Connecting to selected tunnel %s\n", selectedTunnel.Path)
		md := manager.LoadTunnelMetadata(selectedTunnel.Path)

		if md != nil && md.ControllerURL != "" {
			log.Printf("Controller managed tunnel - %s\n", selectedTunnel.Path)
			nc, err := GetControllerInfo(md.ControllerURL)

			if err != nil {
				ShowError("Error talking to controller", fmt.Sprintf("%s", err))
				return err
			}
			accessToken, err := DoOIDCLogin(nc.OidcConfigURL, nc.OidcClientID)
			if err != nil {
				ShowError("Error after OIDC login", fmt.Sprintf("%s", err))
				return err
			}

			err = CreateTempConfig(accessToken, selectedTunnel.Path, nc)

			if err != nil {
				ShowError("Error creating temp config", fmt.Sprintf("%s", err))
				return err
			}
		}

		selectedTunnel.State = manager.TunnelStarting

		tunnel, err := manager.IPCClientStartTunnel(selectedTunnel.Path)
		if err != nil {
			ShowError("Error activating tunnel", fmt.Sprintf("Tunnel start threw error: %s", err))
			return err
		}

		selectedTunnel.State = tunnel.State
		selectedTunnel.Name = tunnel.Name
	}

	return nil
}

func RunUI() {
	manager.LoadTunnelConfigs()

	systray.Run(onReady, onQuit)
}

func onReady() {
	systray.SetTemplateIcon(Icon, Icon)
	systray.SetTitle("Nebula")
	systray.SetTooltip("Nebula")

	for _, t := range manager.CurrentTunnels {
		tunnelMenu := systray.AddMenuItemCheckbox(t.Name, "Active", false)
		activate := tunnelMenu.AddSubMenuItem("Activate", "Activate tunnel")
		deactivate := tunnelMenu.AddSubMenuItem("Deactivate", "Deactivate tunnel")
		deactivate.Disable()
		showLog := tunnelMenu.AddSubMenuItem("Show Log", "Show log")

		t := t
		go func() {
			for {
				select {
				case <-activate.ClickedCh:
					log.Printf("Activate %s\n", t.Name)
					err := ToggleTunnel(&t)
					if err == nil {
						activate.Disable()
						deactivate.Enable()
						tunnelMenu.Check()
					}
				case <-deactivate.ClickedCh:
					log.Printf("Deactivate %s\n", t.Name)
					err := ToggleTunnel(&t)
					if err == nil {
						activate.Enable()
						deactivate.Disable()
						tunnelMenu.Uncheck()
					}
				case <-showLog.ClickedCh:
					cmdToRun := "C:\\Windows\\System32\\notepad.exe"
					args := []string{"notepad.exe", filepath.Join(t.Path, "tunnel.log")}
					procAttr := new(os.ProcAttr)
					procAttr.Files = []*os.File{os.Stdin, os.Stdout, os.Stderr}
					if _, err := os.StartProcess(cmdToRun, args, procAttr); err != nil {
						ShowError("Error displaying log file", fmt.Sprintf("%v", err))
					}
				}
			}
		}()
	}

	systray.AddSeparator()
	mQuitOrig := systray.AddMenuItem("Quit", "Quit Nebula")

	go func() {
		<-mQuitOrig.ClickedCh
		systray.Quit()
	}()
}

func onQuit() {
	_, err := manager.IPCClientQuit(true)

	if err != nil {
		ShowError("Error stopping manager", fmt.Sprintf("%v", err))
	}
}
