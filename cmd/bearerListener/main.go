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
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/xmidt-org/webhook-schema"
	listener "github.com/xmidt-org/wrp-listener"
)

type eventListener struct {
	l   *listener.Listener
	out chan WRPEvent
}

type WRPEvent struct {
	Source          string `json:"source"`
	Destination     string `json:"destination"`
	ContentType     string `json:"content_type"`
	TransactionUUID string `json:"transaction_uuid"`
	DeviceID        string `json:"device_id"`
	DeviceStatus    string `json:"device_status"`
	Firmware        string `json:"firmware"`
}

var goodFirmware = []string{
	"SKXI11ADSSOFT_029.517.00.7.4p33s1_PROD_sdy",
	"SKTL11MEIFT_029.517.00.7.4p33s1_PROD_sdy",
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

	defer w.WriteHeader(http.StatusOK)

	var event WRPEvent
	err = json.Unmarshal(body, &event)
	if err != nil {
		return
	}

	el.out <- event
}

type ListItem struct {
	MAC  string
	When time.Time
}

type List struct {
	lock  sync.Mutex
	Items []ListItem
}

func (l *List) RemoveOldItems() {
	l.lock.Lock()
	defer l.lock.Unlock()
	cutoff := time.Now().Add(-5 * time.Minute)
	var filteredItems []ListItem
	for _, item := range l.Items {
		if item.When.After(cutoff) {
			filteredItems = append(filteredItems, item)
		}
	}
	l.Items = filteredItems
}

func (l *List) SortNewestFirst() {
	l.lock.Lock()
	defer l.lock.Unlock()
	sort.Slice(l.Items, func(i, j int) bool {
		return l.Items[i].When.After(l.Items[j].When)
	})
}

func (l *List) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	l.RemoveOldItems()
	l.SortNewestFirst()
	w.Header().Set("Content-Type", "application/json")

	l.lock.Lock()
	json.NewEncoder(w).Encode(l.Items)
	l.lock.Unlock()
}

func simpleHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hello, world!"))
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
		l:   whl,
		out: make(chan WRPEvent, 1000),
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

	go func() {
		for {
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
	}()

	list := &List{}
	http.Handle("/list", list)
	http.HandleFunc("/", simpleHandler)
	http.ListenAndServe(":9999", nil)
	if err != nil {
		panic(err)
	}

	for {
		event := <-el.out

		good := false
		for _, fw := range goodFirmware {
			if event.Firmware == fw {
				good = true
			}
		}
		if good {
			continue
		}

		now := time.Now()
		list.lock.Lock()
		list.Items = append(list.Items, ListItem{
			MAC:  event.DeviceID,
			When: now,
		})
		list.lock.Unlock()
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
