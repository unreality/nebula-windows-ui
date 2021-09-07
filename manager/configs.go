package manager

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
)

type Tunnel struct {
	Path  string
	Name  string
	State TunnelState
}

type ConfigMetadata struct {
	ControllerURL string `json:"controller_url,omitempty"`
	TunnelName    string `json:"tunnel_name,omitempty"`
	Fingerprint   string `json:"fingerprint,omitempty"`
}

var CurrentTunnels []Tunnel

func LoadTunnelConfigs() {
	configDir, _ := os.UserConfigDir()
	nebulaConfigDir := path.Join(configDir, "Nebula")
	log.Printf("Nebula Config dir is %s", nebulaConfigDir)
	if _, err := os.Stat(nebulaConfigDir); os.IsNotExist(err) {
		err := os.MkdirAll(nebulaConfigDir, 0600)

		if err != nil {
			log.Printf("Couldnt create config dir, no tunnels will be available")
		}
	}

	files, err := ioutil.ReadDir(nebulaConfigDir)
	if err != nil {
		log.Fatalf("Error getting directory listing in %s: %s", nebulaConfigDir, err)
	}

	for _, f := range files {
		if f.IsDir() {
			log.Printf("Checking %s\n", f.Name())
			alreadyExists := false

			for _, t := range CurrentTunnels {
				if t.Name == f.Name() {
					alreadyExists = true
					break
				}
			}

			if alreadyExists {
				continue
			}

			newTun := Tunnel{
				Path:  path.Join(nebulaConfigDir, f.Name()),
				Name:  f.Name(),
				State: TunnelStopped,
			}
			CurrentTunnels = append(CurrentTunnels, newTun)
		}
	}

}

func LoadTunnelMetadata(configPath string) *ConfigMetadata {

	metadataPath := filepath.Join(configPath, "metadata.json")
	metadataRaw, err := ioutil.ReadFile(metadataPath)

	if err != nil {
		return nil
	}

	var metaData ConfigMetadata

	err = json.Unmarshal(metadataRaw, &metaData)

	if err != nil {
		return nil
	}

	return &metaData
}
