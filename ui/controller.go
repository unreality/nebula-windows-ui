package ui

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/elevate"
	"gopkg.in/yaml.v3"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
)

type NebulaConfig struct {
	CertEndpoint       string `json:"certEndpoint"`
	OidcClientID       string `json:"oidcClientID"`
	OidcConfigURL      string `json:"oidcConfigURL"`
	SignEndpoint       string `json:"signEndpoint"`
	NodeConfigEndpoint string `json:"nodeConfigEndpoint"`
	CACert             string `json:"ca"`
}

type SignResponse struct {
	Certificate string              `json:"certificate"`
	StaticHosts map[string][]string `json:"static_host_map"`
	LightHouses []string            `json:"lighthouses"`
	BlockList   []string            `json:"blocklist"`
}

type SignRequest struct {
	PublicKey string `json:"public_key"`
	Duration  int    `json:"duration,omitempty"`
	IP        string `json:"ip,omitempty"`
}

type PKIConfig struct {
	CA        string   `yaml:"ca"`
	Cert      string   `yaml:"cert"`
	Key       string   `yaml:"key"`
	BlockList []string `yaml:"blocklist"`
}

type LighthouseConfig struct {
	AmLighthouse bool     `yaml:"am_lighthouse"`
	Hosts        []string `yaml:"hosts"`
}

type MinNodeConfig struct {
	PKI         PKIConfig           `yaml:"pki"`
	StaticHosts map[string][]string `yaml:"static_host_map"`
	Lighthouse  LighthouseConfig    `yaml:"lighthouse"`
}

var nebulaConfig *NebulaConfig

func fatal(v ...interface{}) {
	if log.Writer() == io.Discard {
		windows.MessageBox(0, windows.StringToUTF16Ptr(fmt.Sprint(v...)), windows.StringToUTF16Ptr(fmt.Sprintf("Error")), windows.MB_ICONERROR)
		os.Exit(1)
	} else {
		log.Fatal(append([]interface{}{fmt.Sprintf("Error: ")}, v...))
	}
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

	err = elevate.ShellExecute(path, "-manager", "", windows.SW_SHOW)
	if err != nil && err != windows.ERROR_CANCELLED {
		return err
	}
	os.Exit(0)
	return windows.ERROR_UNHANDLED_EXCEPTION // Not reached
}

func createTempKey(configDir string) (string, string) {
	var pubkey, privkey [32]byte
	if _, err := io.ReadFull(rand.Reader, privkey[:]); err != nil {
		panic(err)
	}
	curve25519.ScalarBaseMult(&pubkey, &privkey)

	pubKeyPath := path.Join(configDir, "node.pub")

	os.Remove(pubKeyPath)
	err := ioutil.WriteFile(pubKeyPath, cert.MarshalX25519PublicKey(pubkey[:]), 0600)
	if err != nil {
		log.Fatalf("Could not save temp public key!")
	}

	privKeyPath := path.Join(configDir, "node.key")
	os.Remove(privKeyPath)
	err = ioutil.WriteFile(privKeyPath, cert.MarshalX25519PrivateKey(privkey[:]), 0600)
	if err != nil {
		log.Fatalf("error while writing out-key: %s", err)
	}

	log.Printf("Generated temp keypair %s/%s", pubKeyPath, privKeyPath)

	return pubKeyPath, privKeyPath
}

func signPublicKey(nebulaConfig *NebulaConfig, accessToken string, pubKeyFile string) (*SignResponse, error) {

	pubKeyBytes, err := os.ReadFile(pubKeyFile)

	if err != nil {
		return nil, err
	}

	var signReq SignRequest
	signReq.PublicKey = string(pubKeyBytes)
	signReq.Duration = 36000
	signReq.IP = "192.168.11.123/24" // TODO remove this

	signReqJson, err := json.Marshal(signReq)
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	req, err := http.NewRequest("POST", nebulaConfig.SignEndpoint, bytes.NewBuffer(signReqJson))

	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	req.Header.Add("Content-Type", "application/json")

	signResp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	defer signResp.Body.Close()

	if signResp.StatusCode != 200 {
		b, _ := io.ReadAll(signResp.Body)
		log.Fatalf("%s", b)
	}

	var signResponse SignResponse

	err = json.NewDecoder(signResp.Body).Decode(&signResponse)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	return &signResponse, nil
}

func CreateTempConfig(accessToken string, configPath string, nebulaConfig *NebulaConfig) error {
	pubKeyFile, privKeyFile := createTempKey(configPath)

	signResponse, err := signPublicKey(nebulaConfig, accessToken, pubKeyFile)

	certFilePath := filepath.Join(configPath, "node.crt")
	os.Remove(certFilePath)
	out, err := os.Create(certFilePath)
	if err != nil {
		return fmt.Errorf("Could not create certificate file!")
	}
	out.WriteString(signResponse.Certificate)
	out.Close()

	caFilePath := filepath.Join(configPath, "ca.crt")
	os.Remove(caFilePath)
	out, err = os.Create(caFilePath)
	if err != nil {
		return fmt.Errorf("Could not create ca file!")
	}
	out.WriteString(nebulaConfig.CACert)
	out.Close()

	mnc := MinNodeConfig{
		PKI: PKIConfig{
			CA:        filepath.Base(caFilePath),
			Cert:      filepath.Base(certFilePath),
			Key:       filepath.Base(privKeyFile),
			BlockList: signResponse.BlockList,
		},
		StaticHosts: signResponse.StaticHosts,
		Lighthouse: LighthouseConfig{
			AmLighthouse: false,
			Hosts:        signResponse.LightHouses,
		},
	}

	controllerSetConfigPath := filepath.Join(configPath, "zz_controller_config.yml")
	os.Remove(controllerSetConfigPath)
	out, err = os.Create(controllerSetConfigPath)
	if err != nil {
		return fmt.Errorf("Could not create controller config set!")
	}
	outBytes, err := yaml.Marshal(mnc)
	out.Write(outBytes)
	out.Close()

	defaultConfigPath := filepath.Join(configPath, "default.yml")

	if _, err := os.Stat(defaultConfigPath); err == nil {
		// path/to/whatever exists
	} else if os.IsNotExist(err) {
		//copy default config in
		defaultConfigBytes, err := os.ReadFile("default.yml")
		if err != nil {
			return fmt.Errorf("Could not open default.yml!")
		}

		out, err = os.Create(defaultConfigPath)
		if err != nil {
			return fmt.Errorf("Could not copy default.yml!")
		}
		out.Write(defaultConfigBytes)
		out.Close()
	}

	return nil
}

func GetControllerInfo(urlStr string) (*NebulaConfig, error) {
	u, err := url.Parse(urlStr)
	u.Path = path.Join(u.Path, "config")

	client := &http.Client{}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	nebulaConfigResp, err := client.Do(req)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	defer nebulaConfigResp.Body.Close()

	var nebulaConfig NebulaConfig

	err = json.NewDecoder(nebulaConfigResp.Body).Decode(&nebulaConfig)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	return &nebulaConfig, nil
}
