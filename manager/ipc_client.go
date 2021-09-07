package manager

import (
	"encoding/gob"
	"errors"
	"log"
	"os"
	"sync"
)

// Client

type NotificationType int

type TunnelInfo struct {
	Name  string
	State int
}

var tunnelInfo []TunnelInfo

const (
	TunnelChangeNotificationType NotificationType = iota
	TunnelsChangeNotificationType
	TunnelStateNotificationType
	ManagerStoppingNotificationType
)

var (
	rpcEncoder *gob.Encoder
	rpcDecoder *gob.Decoder
	rpcMutex   sync.Mutex
)

type TunnelChangeCallback struct {
	cb func(tunnelName string, state TunnelState, globalState TunnelState, err error)
}

var tunnelChangeCallbacks = make(map[*TunnelChangeCallback]bool)

type TunnelsChangeCallback struct {
	cb func()
}

var tunnelsChangeCallbacks = make(map[*TunnelsChangeCallback]bool)

type ManagerStoppingCallback struct {
	cb func()
}

var managerStoppingCallbacks = make(map[*ManagerStoppingCallback]bool)

func rpcDecodeError() error {
	var str string
	err := rpcDecoder.Decode(&str)
	if err != nil {
		return err
	}
	if len(str) == 0 {
		return nil
	}
	return errors.New(str)
}

func InitializeIPCClient(reader *os.File, writer *os.File, events *os.File) {
	rpcDecoder = gob.NewDecoder(reader)
	rpcEncoder = gob.NewEncoder(writer)
	go func() {
		decoder := gob.NewDecoder(events)
		for {
			var notificationType NotificationType
			err := decoder.Decode(&notificationType)
			if err != nil {
				return
			}
			switch notificationType {
			case TunnelChangeNotificationType:
				var tunnel string
				err := decoder.Decode(&tunnel)
				if err != nil || len(tunnel) == 0 {
					continue
				}
				var state TunnelState
				err = decoder.Decode(&state)
				if err != nil {
					continue
				}
				var globalState TunnelState
				err = decoder.Decode(&globalState)
				if err != nil {
					continue
				}
				var errStr string
				err = decoder.Decode(&errStr)
				if err != nil {
					continue
				}
				var retErr error
				if len(errStr) > 0 {
					retErr = errors.New(errStr)
				}
				if state == TunnelUnknown {
					continue
				}

				for cb := range tunnelChangeCallbacks {
					cb.cb(tunnel, state, globalState, retErr)
				}
			case TunnelsChangeNotificationType:
				for cb := range tunnelsChangeCallbacks {
					cb.cb()
				}
			case ManagerStoppingNotificationType:
				for cb := range managerStoppingCallbacks {
					cb.cb()
				}
			case TunnelStateNotificationType:

				var tunnelName string
				err := decoder.Decode(&tunnelName)
				if err != nil || len(tunnelName) == 0 {
					continue
				}

				var tunnelState int
				err = decoder.Decode(&tunnelState)
				if err != nil {
					continue
				}

				log.Printf("   %s %s\n", tunnelState, tunnelState)

				existingTun := false
				for _, ti := range tunnelInfo {
					if ti.Name == tunnelName {
						ti.State = tunnelState
						existingTun = true
						break
					}
				}

				if existingTun {
					continue
				}

				tunnelInfo = append(tunnelInfo, TunnelInfo{
					Name:  tunnelName,
					State: tunnelState,
				})
			}
		}
	}()
}

func IPCClientTunnelList() []Tunnel {
	return CurrentTunnels
}

func IPCClientQuit(stopTunnelsOnQuit bool) (alreadyQuit bool, err error) {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()

	err = rpcEncoder.Encode(QuitMethodType)
	if err != nil {
		return
	}
	err = rpcEncoder.Encode(stopTunnelsOnQuit)
	if err != nil {
		return
	}
	err = rpcDecoder.Decode(&alreadyQuit)
	if err != nil {
		return
	}
	err = rpcDecodeError()
	return
}

func IPCClientStartTunnel(path string) (tunnel Tunnel, err error) {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()

	err = rpcEncoder.Encode(StartMethodType)
	if err != nil {
		return
	}
	err = rpcEncoder.Encode(path)
	if err != nil {
		return
	}
	err = rpcDecoder.Decode(&tunnel)
	if err != nil {
		return
	}
	err = rpcDecodeError()
	return
}

func IPCClientStopTunnel(tunnelName string) (err error) {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()

	err = rpcEncoder.Encode(StopMethodType)
	if err != nil {
		return
	}
	err = rpcEncoder.Encode(tunnelName)
	if err != nil {
		return
	}
	err = rpcDecodeError()
	return
}
