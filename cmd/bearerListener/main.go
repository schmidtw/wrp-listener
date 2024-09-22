// SPDX-FileCopyrightText: 2023 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xmidt-org/webhook-schema"
	"github.com/xmidt-org/wrp-go/v3"
	listener "github.com/xmidt-org/wrp-listener"
)

// Start

const lifetime = 15 * time.Minute
const cutoff = 15 * time.Second
const maxCount = 100
const frequency = 3*time.Minute + 20*time.Second
const jitter = 10 * time.Second

type eventListener struct {
	l   *listener.Listener
	out chan wrp.Message
}

type targetCPE struct {
	Hardware string
	Firmware string
}

var goodFirmware = []targetCPE{
	{
		Hardware: "SKTL11AEI",
		Firmware: "SKTL11AEI_030.527.00.7.4p31s1_PROD_sdy",
	}, {
		Hardware: "SKXI11ADS",
		Firmware: "SKXI11ADS_030.528.00.7.4p32s1_PROD_sdy",
	}, {
		Hardware: "SKXI11AEISODE",
		Firmware: "SKXI11AEISODE_031.410.01.7.4p32s2_PROD_sdy",
	}, {
		Hardware: "SKTL11MEIIT",
		Firmware: "SKTL11MEIIT_030.528.00.7.4p32s1_PROD_sdy",
	}, {
		Hardware: "SKXI11AENSOIT",
		Firmware: "SKXI11AENSOIT_030.528.00.7.4p32s1_PROD_sdy-signed",
	}, {
		Firmware: "SKXI11ADSSOFT_029.517.00.7.4p33s1_PROD_sdy",
	}, {
		Firmware: "SKTL11MEIFT_029.517.00.7.4p33s1_PROD_sdy",
	},
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

	/*
		fmt.Println("Got a request with body:", string(body))
		fmt.Println("Headers:")
		for k, v := range r.Header {
			fmt.Printf("  %s: %s\n", k, v)
		}
	*/

	var message wrp.Message
	err = wrp.NewDecoderBytes(body, wrp.Msgpack).Decode(&message)
	if err != nil {
		//fmt.Println("Failed to decode WRP message:", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	//fmt.Println("Got a good WRP message.")
	el.out <- message
}

type ListItem struct {
	MAC      string
	BootTime time.Time
	When     time.Time
}

type List struct {
	lock  sync.Mutex
	Items []ListItem
}

func (l *List) RemoveOldItems() {
	l.removeOldItems(-1 * lifetime)
}

func (l *List) removeOldItems(d time.Duration) {
	l.lock.Lock()
	defer l.lock.Unlock()
	cutoff := time.Now().Add(d)
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

func (l *List) GetAverageBootTime() time.Duration {
	if len(l.Items) == 0 {
		return 0
	}

	var total time.Duration
	count := 0
	for idx, item := range l.Items {
		if !item.BootTime.IsZero() && idx < maxCount &&
			item.BootTime.Before(item.When.Add(time.Hour)) &&
			item.BootTime.After(item.When.Add(-1*time.Hour)) {
			total += item.When.Sub(item.BootTime)
			count++
		}
	}

	if count == 0 {
		return 0
	}

	return total / time.Duration(count)
}

func (l *List) GiveMeBoxesISawBefore(d time.Duration) []string {
	j := time.Duration(float64(jitter) * (0.5 - 0.5*rand.Float64()))
	d += j
	l.lock.Lock()
	defer l.lock.Unlock()
	cutoff := time.Now().Add(-1 * lifetime)
	var macs []string
	now := time.Now()
	for idx, item := range l.Items {
		if idx < maxCount {
			if item.When.After(cutoff) {
				//|| (item.When.After(cutoff) && item.When.Before(cutoff.Add(time.Second*20))) {
				macs = append(macs, item.MAC)
				fmt.Printf("%s: %s\n", item.MAC, item.When.Sub(now))
			}
		}
	}
	return macs
}

func (l *List) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	l.OffendersHTTP(w, r)
}

func (l *List) RecentServeHTTP(w http.ResponseWriter, r *http.Request) {
	l.RemoveOldItems()
	l.SortNewestFirst()
	w.Header().Set("Content-Type", "application/text")

	w.Header().Set("X-BootTimeLatency", l.GetAverageBootTime().String())

	/*
		for idx, item := range l.Items {
			if idx < maxCount && item.BootTime.Before(item.When.Add(time.Hour)) &&
				item.BootTime.After(item.When.Add(-1*time.Hour)) {
				w.Header().Add("X-BootTimeRoot", item.BootTime.String())
			}
		}
	*/
	got := l.GiveMeBoxesISawBefore(frequency)
	for _, mac := range got {
		fmt.Fprintf(w, "%s\n", mac)
	}
}

func (l *List) OffendersHTTP(w http.ResponseWriter, r *http.Request) {
	l.SortNewestFirst()
	w.Header().Set("Content-Type", "application/text")
	l.SortNewestFirst()
	w.Header().Set("Content-Type", "application/text")

	offeners := make(map[string]int)
	for _, item := range l.Items {
		offeners[item.MAC]++
	}

	// sort the offendders by count
	sort.Slice(l.Items, func(i, j int) bool {
		return offeners[l.Items[i].MAC] > offeners[l.Items[j].MAC]
	})

	for mac, count := range offeners {
		//w.Header().Add("X-Offender", fmt.Sprintf("%s: %d", mac, count))
		fmt.Printf("%s: %d\n", mac, count)
	}

	for mac := range offeners {
		fmt.Fprintf(w, "%s\n", mac)
	}
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

	for i := range sharedSecrets {
		sharedSecrets[i] = strings.TrimSpace(sharedSecrets[i])
	}

	// Create the listener.
	whl, err := listener.New(webhookURL,
		&webhook.Registration{
			Config: webhook.DeliveryConfig{
				ReceiverURL: receiverURL,
				ContentType: "application/msgpack",
			},
			Events: []string{
				"device-status/.*/online",
			},
			Duration: webhook.CustomDuration(5 * time.Minute),
		},
		listener.DecorateRequest(listener.DecoratorFunc(
			func(r *http.Request) error {
				sat, err := getSat()
				if err != nil {
					panic(err)
				}
				r.Header.Set("Authorization", "Bearer "+sat)
				return nil
			},
		)),
		listener.AcceptSHA1(),
		listener.AcceptSHA256(),
		listener.Interval(time.Minute),
		listener.AcceptedSecrets(sharedSecrets...),
	)
	if err != nil {
		panic(err)
	}

	fmt.Println(whl.String())

	el := eventListener{
		l:   whl,
		out: make(chan wrp.Message, 1000),
	}

	whl.Register(context.Background(), sharedSecrets[0])

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

	happy := &List{}

	go func() {
		for {
			time.Sleep(5 * time.Minute)
			f, err := os.Create("/tmp/happy.txt")
			if err != nil {
				continue

			}
			happy.removeOldItems(-1 * time.Hour)
			for _, item := range happy.Items {
				fmt.Fprintf(f, "%s\n", item.MAC)
			}
			f.Close()
		}
	}()

	list := &List{}
	go func() {
		for {
			event := <-el.out

			good := true
			for _, fw := range goodFirmware {
				if strings.ToLower(event.Metadata["/hw-model"]) == strings.ToLower(fw.Hardware) ||
					fw.Hardware == "" {
					if strings.ToLower(event.Metadata["/fw-name"]) != strings.ToLower(fw.Firmware) {
						//fmt.Printf("Bad %s -- %s\n", event.Metadata["/hw-model"], event.Metadata["/fw-name"])
						good = false
					}
				}

			}
			//fmt.Println("Bad firmware:", event.Metadata["/fw-name"])

			/*
				bt := strings.TrimSpace(event.Metadata["boot-time"])
				if bt != "" {
					unixTime, err := strconv.ParseInt(bt, 10, 64)
					if err != nil {
						fmt.Println("Failed to parse boot-time:", bt)
						continue
					}
					bootTime := time.Unix(unixTime, 0)
					if time.Since(bootTime) > 15*time.Minute {
						continue
					}
				}
			*/

			var payload map[string]any
			err = json.Unmarshal(event.Payload, &payload)
			if err != nil {
				continue
			}

			now := time.Now()

			if good {
				happy.lock.Lock()
				happy.Items = append(happy.Items, ListItem{
					MAC:  payload["id"].(string),
					When: now,
				})
				happy.lock.Unlock()
				continue
			}

			list.lock.Lock()
			bt := strings.TrimSpace(event.Metadata["/boot-time"])
			bootedAt := time.Time{}
			if bt != "" {
				unixTime, err := strconv.ParseInt(bt, 10, 64)
				if err == nil {
					bootedAt = time.Unix(unixTime, 0)
				}
			}
			list.Items = append(list.Items, ListItem{
				MAC:      payload["id"].(string),
				BootTime: bootedAt,
				When:     now,
			})
			list.lock.Unlock()
		}
	}()

	http.Handle("/list", list)
	http.HandleFunc("/", simpleHandler)
	http.ListenAndServe(":9999", nil)
	if err != nil {
		panic(err)
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
