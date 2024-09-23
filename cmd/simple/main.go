package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
)

const macAddress = "mac:04B86A16E326"

//D058FCFFFA73"

type SatResponse struct {
	ExpiresIn          int    `json:"expires_in"`
	ServiceAccessToken string `json:"serviceAccessToken"`
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

func setParam(creds, mac string, set Parameters) error {
	client := &http.Client{}

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

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}

func main() {
	token, err := getSat()
	if err != nil {
		panic(err)
	}

	err = setParam(token, macAddress,
		Parameters{
			Parameters: []Parameter{
				{
					Name:     "Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.newNTP.Enable",
					Value:    "true",
					DataType: 3, // boolean
				},
				{
					Name:     "Device.Time.NTPServer1",
					Value:    "3.236.252.118",
					DataType: 0, // string
				},
				{
					Name:     "Device.Time.NTPServer2",
					Value:    "3.236.252.118",
					DataType: 0, // string
				},
				{
					Name:     "Device.Time.NTPServer3",
					Value:    "3.236.252.118",
					DataType: 0, // string
				},
				{
					Name:     "Device.Time.NTPServer4",
					Value:    "3.236.252.118",
					DataType: 0, // string
				},
				{
					Name:     "Device.Time.NTPServer5",
					Value:    "3.236.252.118",
					DataType: 0, // string
				},
			},
		})

	if err != nil {
		panic(err)
	}
}
