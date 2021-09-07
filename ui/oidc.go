package ui

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"time"
)

type OpenIDConfiguration struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

type OpenIDTokens struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	IdToken          string `json:"id_token"`
	NotBeforePolicy  int    `json:"not-before-policy,omitempty"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	RefreshToken     string `json:"refresh_token"`
	Scope            string `json:"scope"`
	SessionState     string `json:"session_state,omitempty"`
	TokenType        string `json:"token_type,omitempty"`
}

func getOIDCConfig(oidcConfigURL string) (*OpenIDConfiguration, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", oidcConfigURL, nil)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	oidcConfigResp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	defer oidcConfigResp.Body.Close()

	var oidcConfig OpenIDConfiguration

	err = json.NewDecoder(oidcConfigResp.Body).Decode(&oidcConfig)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	return &oidcConfig, nil
}

func DoOIDCLogin(oidcConfigURL string, oidcClientID string) (string, error) {
	oidcConfig, err := getOIDCConfig(oidcConfigURL)

	if err != nil {
		return "", errors.New("Could not retrieve OIDC config")
	}

	b := make([]byte, 3*16)
	_, err = rand.Read(b)
	v := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b)

	vSHABytes := sha256.Sum256([]byte(v))
	vSHA := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(vSHABytes[:])

	if err != nil {
		return "", errors.New("Could not read 64 bytes of crypto")
	}

	params := url.Values{}
	params.Add("response_type", "code")
	params.Add("client_id", oidcClientID)
	params.Add("redirect_uri", "http://localhost:4242/")
	params.Add("scope", "openid")
	params.Add("code_challenge_method", "S256")
	params.Add("code_challenge", vSHA)

	authUrl := fmt.Sprintf("%s?%s", oidcConfig.AuthorizationEndpoint, params.Encode())

	log.Printf("Opening %s\n", authUrl)
	var cmd *exec.Cmd
	cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", authUrl)
	cmd.Start()

	otp, _ := waitForOTP(90, 4242)

	if otp == "" {
		return "", errors.New("timed out waiting for auth login")
	}

	params = url.Values{}
	params.Add("grant_type", "authorization_code")
	params.Add("code", otp)
	params.Add("client_id", oidcClientID)
	params.Add("redirect_uri", "http://localhost:4242/")
	params.Add("code_verifier", v)

	client := &http.Client{}
	req, err := http.NewRequest("POST", oidcConfig.TokenEndpoint, strings.NewReader(params.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	if err != nil {
		log.Println(err)
		return "", err
	}

	tokenResp, err := client.Do(req)
	if err != nil {
		log.Println(err)
		return "", err
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != 200 {
		b, _ := io.ReadAll(tokenResp.Body)
		log.Fatalf("%s", b)
	}

	var tokens OpenIDTokens

	err = json.NewDecoder(tokenResp.Body).Decode(&tokens)
	if err != nil {
		log.Println(err)
		return "", err
	}
	return tokens.AccessToken, nil
}

func waitForOTP(timeout int, callbackPort int) (string, string) {

	var srv http.Server
	var otp string
	var state string

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(timeout))
	defer cancel()

	srv = http.Server{
		Addr: fmt.Sprintf("127.0.0.1:%d", callbackPort),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			otps, otpOK := r.URL.Query()["code"]
			states, stateOK := r.URL.Query()["session_state"]

			if otpOK && stateOK && len(otps) > 0 && len(states) > 0 {
				otp = otps[0]
				state = states[0]
				io.WriteString(w, fmt.Sprintf("<html><head><title>Authorization Succeeded</title></head><body><h4>Login Succeeded</h4></body></html>"))
				cancel()

			} else {
				io.WriteString(w, fmt.Sprintf("<html><body><h4>Error reading OTP from request</h4></body></html>"))
				w.WriteHeader(400)
			}

		}),
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	log.Printf("Starting OTP server")

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP Listen threw error: %v", err)
		}
	}()
	select {
	case <-ctx.Done():
		// Shutdown the server when the context is canceled
		_ = srv.Shutdown(ctx)
	}

	return otp, state
}
