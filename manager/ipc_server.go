package manager

import (
	"encoding/gob"
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
)

type MethodType int

const (
	StartMethodType MethodType = iota
	StopMethodType
	WaitForStopMethodType
	StateMethodType
	QuitMethodType
)

type TunnelState int

const (
	TunnelUnknown TunnelState = iota
	TunnelStarted
	TunnelStopped
	TunnelStarting
	TunnelStopping
)

var managerServices = make(map[*ManagerService]bool)
var managerServicesLock sync.RWMutex
var haveQuit uint32
var quitManagersChan = make(chan struct{}, 1)

type ManagerService struct {
	events        *os.File
	eventLock     sync.Mutex
	elevatedToken windows.Token
}

func errToString(err error) string {
	if err != nil {
		return fmt.Sprintf("%s", err)
	}

	return ""
}

func (s *ManagerService) State(tunnelName string) (TunnelState, error) {
	return TunnelStopped, nil
}

func (s *ManagerService) Start(configPath string) (*Tunnel, error) {
	tunnelName := filepath.Base(configPath)
	err := InstallTunnelService(tunnelName, configPath)

	if err != nil {
		return nil, err
	}

	t := Tunnel{
		Path:  configPath,
		Name:  tunnelName,
		State: TunnelStarted,
	}
	CurrentTunnels = append(CurrentTunnels, t)

	return &t, nil
}

func (s *ManagerService) Stop(tunnelName string) error {
	return UninstallTunnelService(tunnelName)
}

func (s *ManagerService) WaitForStop(tunnelName string) error {
	return nil
}

func (s *ManagerService) Quit(stopTunnelsOnQuit bool) (alreadyQuit bool, err error) {
	if s.elevatedToken == 0 {
		return false, windows.ERROR_ACCESS_DENIED
	}
	if !atomic.CompareAndSwapUint32(&haveQuit, 0, 1) {
		return true, nil
	}

	// Work around potential race condition of delivering messages to the wrong process by removing from notifications.
	managerServicesLock.Lock()
	s.eventLock.Lock()
	s.events = nil
	s.eventLock.Unlock()
	delete(managerServices, s)
	managerServicesLock.Unlock()

	if stopTunnelsOnQuit {

		for _, t := range CurrentTunnels {
			UninstallTunnelService(t.Name)
		}
	}

	quitManagersChan <- struct{}{}
	return false, nil
}

func (s *ManagerService) ServeConn(reader io.Reader, writer io.Writer) {
	decoder := gob.NewDecoder(reader)
	encoder := gob.NewEncoder(writer)
	for {
		var methodType MethodType
		err := decoder.Decode(&methodType)
		if err != nil {
			return
		}
		switch methodType {

		case StartMethodType:
			var configPath string
			err := decoder.Decode(&configPath)
			if err != nil {
				return
			}
			tun, retErr := s.Start(configPath)
			err = encoder.Encode(tun)
			if err != nil {
				return
			}
			err = encoder.Encode(errToString(retErr))
			if err != nil {
				return
			}
		case StopMethodType:
			var tunnelName string
			err := decoder.Decode(&tunnelName)
			if err != nil {
				return
			}
			retErr := s.Stop(tunnelName)
			err = encoder.Encode(errToString(retErr))
			if err != nil {
				return
			}
		case WaitForStopMethodType:
			var tunnelName string
			err := decoder.Decode(&tunnelName)
			if err != nil {
				return
			}
			retErr := s.WaitForStop(tunnelName)
			err = encoder.Encode(errToString(retErr))
			if err != nil {
				return
			}
		case StateMethodType:
			var tunnelName string
			err := decoder.Decode(&tunnelName)
			if err != nil {
				return
			}
			state, retErr := s.State(tunnelName)
			err = encoder.Encode(state)
			if err != nil {
				return
			}
			err = encoder.Encode(errToString(retErr))
			if err != nil {
				return
			}
		case QuitMethodType:
			var stopTunnelsOnQuit bool
			err := decoder.Decode(&stopTunnelsOnQuit)
			if err != nil {
				return
			}
			alreadyQuit, retErr := s.Quit(stopTunnelsOnQuit)
			err = encoder.Encode(alreadyQuit)
			if err != nil {
				return
			}
			err = encoder.Encode(errToString(retErr))
			if err != nil {
				return
			}
		default:
			return
		}
	}
}

func IPCServerListen(reader *os.File, writer *os.File, events *os.File, elevatedToken windows.Token) {
	service := &ManagerService{
		events:        events,
		elevatedToken: elevatedToken,
	}

	go func() {
		managerServicesLock.Lock()
		managerServices[service] = true
		managerServicesLock.Unlock()
		service.ServeConn(reader, writer)
		managerServicesLock.Lock()
		service.eventLock.Lock()
		service.events = nil
		service.eventLock.Unlock()
		delete(managerServices, service)
		managerServicesLock.Unlock()
	}()
}
