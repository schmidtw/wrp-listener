// SPDX-FileCopyrightText: 2023 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/k0kubun/pp"
	"github.com/xmidt-org/webhook-schema"
	"github.com/xmidt-org/wrp-go/v3"
	listener "github.com/xmidt-org/wrp-listener"
)

// Start

const filename = "/tmp/state.json"

const lifetime = 15 * time.Minute

// const cutoff = 15 * time.Second
const maxCount = 300
const frequency = 3*time.Minute + 20*time.Second
const jitter = 10 * time.Second

const tr181ParameterGET = "Device.DeviceInfo.SerialNumber"

const ntpServer = "wesotron.sed.dh.comcast.net"

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
		Firmware: "SKTL11MEIFT_029.517.00.7.4p33s1_PROD_sdy",
		Hardware: "SKTL11MEIFT",
	}, {
		Firmware: "SKXI11ADSSOFT_029.517.00.7.4p33s1_PROD_sdy",
		Hardware: "SKXI11ADSSOFT",
	},

	{
		Hardware: "SKXI11ADS",
		Firmware: "SKXI11ADS_030.528.00.7.4p32s1_PROD_sdy",
	}, {
		Hardware: "SKTL11AEI",
		Firmware: "SKTL11AEI_030.527.00.7.4p31s1_PROD_sdy",
	}, {
		Hardware: "SKXI11AENSOIT",
		Firmware: "SKXI11AENSOIT_030.528.00.7.4p32s1_PROD_sdy",
	},

	{
		Hardware: "SKXI11AEISODE",
		Firmware: "SKXI11AEISODE_031.410.01.7.4p32s2_PROD_sdy",
	}, {
		Hardware: "SKTL11MEIIT",
		Firmware: "SKTL11MEIIT_030.528.00.7.4p32s1_PROD_sdy",
	}, {
		Hardware: "SKXI11AENSOIT",
		Firmware: "SKXI11AENSOIT_030.528.00.7.4p32s1_PROD_sdy-signed",
	},
}

var badFirmware = []targetCPE{
	{
		Hardware: "SKXI11ADS",
		Firmware: "SKXI11ADS_028.516.00.6.11p28s1_PROD_sdy",
	}, {
		Hardware: "SKXI11ADS",
		Firmware: "SKXI11ADS_030.525.00.7.4p30s1_PROD_sdy",
	}, {
		Hardware: "SKXI11ADS",
		Firmware: "SKXI11ADS_030.525.00.7.4p30s1_PROD_sdy",
	}, {
		Hardware: "SKXI11ADS",
		Firmware: "SKXI11ADS_030.525.00.7.4p30s1_PROD_sdy",
	},

	{
		Hardware: "SKXI11AEISODE",
		Firmware: "SKTL11AEI_030.524.00.7.4p27s1_PROD_sdy",
	}, {
		Hardware: "SKXI11AEISODE",
		Firmware: "SKTL11AEI_030.520.00.7.4p25s2_PROD_sdy",
	}, {
		Hardware: "SKXI11AEISODE",
		Firmware: "SKTL11AEI_028.516.00.6.11p28s1_PROD_sdy",
	},

	{
		Hardware: "SKXI11AENSOIT",
		Firmware: "SKXI11AENSOIT_028.520.00.6.11p31s1_PROD_sdy",
	}, {
		Hardware: "SKXI11AENSOIT",
		Firmware: "SKXI11AENSOIT_030.526.00.7.4p30s2_PROD_sdy",
	},

	{
		Hardware: "SKTL11MEIIT",
		Firmware: "SKTL11MEIIT_028.520.00.6.11p31s1_PROD_sdy",
	}, {
		Hardware: "SKTL11MEIIT",
		Firmware: "SKTL11MEIIT_030.519.00.7.4p25s1_PROD_sdy",
	},

	{
		Hardware: "SKTL11MEIFT",
		Firmware: "SKTL11MEIFT_029.506.00.7.4p6s1_PROD_sdy",
	}, {
		Hardware: "SKTL11MEIFT",
		Firmware: "SKTL11MEIFT_029.506.01.7.4p29s1_PROD_sdy",
	},

	{
		Firmware: "SKXI11ADSSOFT_029.506.00.7.4p6s1_PROD_sdy",
		Hardware: "SKXI11ADSSOFT",
	}, {
		Firmware: "SKXI11ADSSOFT_029.506.01.7.4p29s1_PROD_sdy",
		Hardware: "SKXI11ADSSOFT",
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
	until := time.Now().Add(d)
	var filteredItems []ListItem
	for _, item := range l.Items {
		if item.When.After(until) {
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
	until := time.Now().Add(-1 * lifetime)
	var macs []string
	now := time.Now()
	for idx, item := range l.Items {
		if idx < maxCount {
			if item.When.After(until) {
				//|| (item.When.After(until) && item.When.Before(until.Add(time.Second*20))) {
				macs = append(macs, item.MAC)
				fmt.Printf("%s: %s\n", item.MAC, item.When.Sub(now))
			}
		}
	}
	return macs
}

func (l *List) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	l.OffendersHTTP(w, r)
	//w.WriteHeader(http.StatusOK)
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
	l.RemoveOldItems()
	l.SortNewestFirst()
	w.Header().Set("Content-Type", "application/text")

	offenders := make(map[string]int)
	for _, item := range l.Items {
		offenders[item.MAC]++
	}

	// Extract keys and sort them by their values in descending order
	type kv struct {
		Key   string
		Value int
	}

	sortedOffenders := make([]kv, 0, len(offenders))
	for k, v := range offenders {
		sortedOffenders = append(sortedOffenders, kv{k, v})
	}

	sort.Slice(sortedOffenders, func(i, j int) bool {
		return sortedOffenders[i].Value > sortedOffenders[j].Value
	})

	// Output the sorted offenders
	//fmt.Println("--------------------")
	//fmt.Printf("Offenders:\n")
	for idx, kv := range sortedOffenders {
		if idx < maxCount {
			//fmt.Printf("%s: %d\n", kv.Key, kv.Value)
			fmt.Fprintf(w, "%s\n", kv.Key)
		}
	}
}

func simpleHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hello, world!"))
}

var satToken string
var targets []string

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

	var err error
	satToken, err = getSat()
	if err != nil {
		panic(err)
	}

	tmp := strings.Split(os.Getenv("TARGET_CPE"), ",")
	targets = make([]string, 0, len(tmp))
	for _, item := range tmp {
		targets = append(targets, strings.TrimSpace(item))
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
			/*
				for _, fw := range goodFirmware {
					eHw := strings.ToLower(event.Metadata["/hw-model"])
					eFw := strings.ToLower(event.Metadata["/fw-name"])

					// Ignore empty string boxes
					if eHw == "" || eFw == "" {
						continue
					}

					// Ignore Dev builds
					if strings.Contains(eFw, "VBN") {
						continue
					}

					if eHw == strings.ToLower(fw.Hardware) && eFw != strings.ToLower(fw.Firmware) {
						good = false
					}
				}
			*/
			eFw := strings.ToLower(event.Metadata["/fw-name"])
			for _, fw := range badFirmware {
				//eHw := strings.ToLower(event.Metadata["/hw-model"])

				// Ignore empty string boxes
				if eFw == "" {
					continue
				}

				// Ignore Dev builds
				if strings.Contains(eFw, "VBN") {
					continue
				}

				//if eHw == strings.ToLower(fw.Hardware) && eFw == strings.ToLower(fw.Firmware) {
				if eFw == strings.ToLower(fw.Firmware) {
					good = false
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

			macAddress := payload["id"].(string)
			now := time.Now()

			for _, target := range targets {
				if strings.Contains(strings.ToLower(macAddress), target) {
					fmt.Println("We found a target CPE!: ", macAddress)
					//good = false
				}
			}

			if good {
				happy.lock.Lock()
				happy.Items = append(happy.Items, ListItem{
					MAC:  payload["id"].(string),
					When: now,
				})
				happy.lock.Unlock()
				continue
			}

			go muckWithTr181(macAddress, eFw)

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

type Parameter struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	DataType int    `json:"dataType"`
}

type Parameters struct {
	Parameters     []Parameter `json:"parameters"`
	DataType       int         `json:"dataType"`
	ParameterCount int         `json:"parameterCount,omitempty"`
	Message        string      `json:"message,omitempty"`
}

type Response struct {
	Parameters []Parameters `json:"parameters"`
	StatusCode int          `json:"statusCode"`
}

func getParam(creds, mac, fields string) (Response, int, error) {
	var result Response
	client := &http.Client{}

	u, err := url.ParseRequestURI(os.Getenv("WEBHOOK_URL"))
	if err != nil {
		return Response{}, 0, err
	}

	q := u.Query()
	q.Add("names", url.QueryEscape(fields))
	u.Path = "/api/v3/device/" + url.PathEscape(mac) + "/config"
	u.RawQuery = q.Encode()

	fmt.Println("URL:", u.String())

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return Response{}, 0, err
	}

	req.Header.Set("Authorization", "Bearer "+creds)

	resp, err := client.Do(req)
	if err != nil {
		return Response{}, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Response{}, resp.StatusCode, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return Response{}, resp.StatusCode, err
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return result, resp.StatusCode, err
	}

	return result, resp.StatusCode, nil
}

func setParam(creds, mac string, set Parameters) error {
	client := &http.Client{
		Timeout: 150 * time.Second,
	}

	u, err := url.ParseRequestURI(os.Getenv("WEBHOOK_URL"))
	if err != nil {
		return err
	}

	u.Path = "/api/v3/device/" + url.PathEscape(mac) + "/config"

	// Marshal the Parameters struct into JSON
	jsonData, err := json.Marshal(set)
	if err != nil {
		return err
	}

	// Create a bytes.Reader from the JSON byte slice
	bodyReader := bytes.NewReader(jsonData)

	req, err := http.NewRequest("PATCH", u.String(), bodyReader)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+creds)
	req.Header.Set("Content-Type", "application/json")

	fmt.Println("PATCH URL:", u.String())

	resp, err := client.Do(req)

	fmt.Println("====== I  got something  ==================")
	if err != nil {
		fmt.Printf("There was an error: %s\n", err)
		return err
	}
	fmt.Printf("Status code: %d\n", resp.StatusCode)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}

func getFakeNTP() Parameters {
	return Parameters{
		Parameters: []Parameter{
			{
				Name:     "Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.newNTP.Enable",
				Value:    "true",
				DataType: 3, // boolean
			},
			{
				Name:     "Device.Time.NTPServer1",
				Value:    ntpServer,
				DataType: 0, // string
			},
			{
				Name:     "Device.Time.NTPServer2",
				Value:    ntpServer,
				DataType: 0, // string
			},
		},
	}
}

func getJoesNTP() Parameters {
	return Parameters{
		Parameters: []Parameter{
			{
				Name:     "Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.newNTP.Enable",
				Value:    "true",
				DataType: 3, // boolean
			},
			{
				Name:     "Device.Time.NTPServer1",
				Value:    "1.1.1.1",
				DataType: 0, // string
			},
			{
				Name:     "Device.Time.NTPServer2",
				Value:    "2.2.2.2",
				DataType: 0, // string
			},
			{
				Name:     "Device.Time.NTPServer3",
				Value:    "3.3.3.3",
				DataType: 0, // string
			},
			{
				Name:     "Device.Time.NTPServer4",
				Value:    "4.4.4.4",
				DataType: 0, // string
			},
			{
				Name:     "Device.Time.NTPServer5",
				Value:    "devicetime1.sky.com",
				DataType: 0, // string
			},
		},
	}
}

//time.streamotion.com.au
//time2.streamotion.com.au

func getRestoreNTP() Parameters {
	return Parameters{
		Parameters: []Parameter{
			{
				Name:     "Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.newNTP.Enable",
				Value:    "false",
				DataType: 3, // boolean
			},
			{
				Name:     "Device.Time.NTPServer1",
				Value:    "devicetime1.sky.com",
				DataType: 0, // string
			},
			{
				Name:     "Device.Time.NTPServer2",
				Value:    "devicetime2.sky.com",
				DataType: 0, // string
			},
		},
	}
}

func muckWithTr181(mac, fw string) {

	var found bool
	for _, target := range targets {
		//fmt.Printf("%s ? %s\n", strings.ToLower(mac), strings.ToLower(target))
		if strings.Contains(strings.ToLower(mac), strings.ToLower(target)) {
			fmt.Println("We found a target CPE!: ", mac)
			fmt.Printf("We found a target CPE!: %s, firmware: '%s'\n", mac, fw)
			found = true
		}
	}

	if !found {
		return
	}

	fmt.Println("------------------")
	fmt.Println("Mucking with TR-181 for", mac)
	fmt.Println("------------------")

	for {
		resp, code, err := getParam(satToken, mac, tr181ParameterGET)
		//resp, code, err := getParam(satToken, mac, "Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.newNTP.Enable,Device.Time.NTPServer1,Device.Time.NTPServer2,Device.Time.NTPServer3,Device.Time.NTPServer4,Device.Time.NTPServer5") //tr181ParameterGET)
		if err != nil {
			fmt.Println("Failed to get TR-181 parameter:", err)
		} else {
			pp.Println(resp)
		}

		if code == http.StatusOK {
			break
		}
		if code == http.StatusNotFound {
			fmt.Println("We missed it.")
			return
		}
	}

	if false {
		fmt.Println("Not mucking with TR-181 for", mac)
		return
	}

	params := getJoesNTP()
	//params := getFakeNTP()
	//params := getRestoreNTP()

	err := setParam(satToken, mac, params)
	if err != nil {
		fmt.Println("Failed to set TR-181 parameter:", err)
	} else {
		fmt.Println("Successfully set TR-181 parameter")
	}

	resp, _, err := getParam(satToken, mac, "Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.newNTP.Enable,Device.Time.NTPServer1,Device.Time.NTPServer2,Device.Time.NTPServer3,Device.Time.NTPServer4,Device.Time.NTPServer5")
	if err != nil {
		fmt.Println("Failed to get TR-181 parameter:", err)
	} else {
		pp.Println(resp)
	}
}
