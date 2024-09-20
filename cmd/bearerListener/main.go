// SPDX-FileCopyrightText: 2023 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/xmidt-org/webhook-schema"
	listener "github.com/xmidt-org/wrp-listener"
)

type eventListener struct {
	l *listener.Listener
}

func (el *eventListener) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token, err := el.l.Tokenize(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Println("Got a request, but it was not authorized.")
		return
	}

	err = el.l.Authorize(r, token)
	if err != nil {
		fmt.Println("Got a request, but it was not authorized.")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	body, err := io.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		fmt.Println("Got a request, but it had no body.")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	fmt.Println(string(body))

	w.WriteHeader(http.StatusOK)
}

func main() {
	receiverURL := strings.TrimSpace(os.Getenv("WEBHOOK_TARGET"))
	webhookURL := strings.TrimSpace(os.Getenv("WEBHOOK_URL"))
	localAddress := strings.TrimSpace(os.Getenv("WEBHOOK_LISTEN_ADDR"))
	certFile := strings.TrimSpace(os.Getenv("WEBHOOK_LISTEN_CERT_FILE"))
	keyFile := strings.TrimSpace(os.Getenv("WEBHOOK_LISTEN_KEY_FILE"))
	sharedSecrets := strings.Split(os.Getenv("WEBHOOK_SHARED_SECRETS"), ",")

	useTLS := false
	if certFile != "" && keyFile != "" {
		useTLS = true
	}

	fmt.Println("WEBHOOK_TARGET          : ", receiverURL)
	fmt.Println("WEBHOOK_URL             : ", webhookURL)
	fmt.Println("WEBHOOK_LISTEN_ADDR     : ", localAddress)
	fmt.Println("WEBHOOK_LISTEN_CERT_FILE: ", certFile)
	fmt.Println("WEBHOOK_LISTEN_KEY_FILE : ", keyFile)
	fmt.Println("WEBHOOK_SHARED_SECRETS  : ", sharedSecrets)
	fmt.Println("SAT_URL                 : ", os.Getenv("SAT_URL"))
	fmt.Println("SAT_CLIENT_ID           : ", os.Getenv("SAT_CLIENT_ID"))
	fmt.Println("SAT_CLIENT_SECRET       : ", os.Getenv("SAT_CLIENT_SECRET"))
	fmt.Printf("                 use TLS: %t\n", useTLS)

	sat, err := getSat()
	if err != nil {
		panic(err)
	}

	for i := range sharedSecrets {
		sharedSecrets[i] = strings.TrimSpace(sharedSecrets[i])
	}

	// Create the listener.
	whl, err := listener.New(webhookURL,
		&webhook.Registration{
			Config: webhook.DeliveryConfig{
				ReceiverURL: receiverURL,
				ContentType: "application/json",
			},
			Events: []string{"device-status"},
			//Duration: webhook.CustomDuration(5 * time.Minute),
			Duration: webhook.CustomDuration(15 * time.Second),
		},
		listener.DecorateRequest(listener.DecoratorFunc(
			func(r *http.Request) error {
				if os.Getenv("WEBHOOK_BEARER_TOKEN") == "" {
					return nil
				}
				r.Header.Set("Authorization", "Bearer "+sat)
				return nil
			},
		)),
		listener.AcceptSHA1(),
		listener.Once(),
		listener.AcceptedSecrets(sharedSecrets...),
	)
	if err != nil {
		panic(err)
	}

	fmt.Println(whl.String())

	el := eventListener{
		l: whl,
	}

	go func() {
		if useTLS {
			err := http.ListenAndServeTLS(localAddress, certFile, keyFile, &el) // nolint: gosec
			if err != nil {
				panic(err)
			}
		} else {
			err := http.ListenAndServe(localAddress, &el) // nolint: gosec
			if err != nil {
				panic(err)
			}
		}
	}()

	// Register for webhook events, using the secret "foobar" as the shared
	// secret.
	err = whl.Register(context.Background(), sharedSecrets[0])
	if err != nil {
		panic(err)
	}

	for {
		time.Sleep(1 * time.Minute)
	}
}

type SatResponse struct {
	ExpiresIn          int    `json:"expires_in"`
	ServiceAccessToken string `json:"serviceAccessToken"`
}

func getSat() (string, error) {
	client := &http.Client{}
	satURL := os.Getenv("SAT_URL")
	req, err := http.NewRequest("GET", satURL, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Client-Id", os.Getenv("SAT_CLIENT_ID"))
	req.Header.Set("X-Client-Secret", os.Getenv("SAT_CLIENT_SECRET"))

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var satResponse SatResponse
	err = json.Unmarshal(body, &satResponse)
	if err != nil {
		return "", err
	}

	return satResponse.ServiceAccessToken, nil
}
