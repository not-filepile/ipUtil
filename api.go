package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

type InternetDBResponse struct {
	IP        string   `json:"ip"`
	Hostnames []string `json:"hostnames"`
	Ports     []int    `json:"ports"`
	Tags      []string `json:"tags"`
	Vulns     []string `json:"vulns"`
	CPEs      []string `json:"cpes"`
}

type IpinfoResponse struct {
	IP       string `json:"ip"`
	City     string `json:"city"`
	Region   string `json:"region"`
	Country  string `json:"country"`
	Loc      string `json:"loc"`
	Org      string `json:"org"`
	Postal   string `json:"postal"`
	Timezone string `json:"timezone"`
}

func queryInternetDB(ipAddress string) (*InternetDBResponse, error) {
	resp, err := http.Get(fmt.Sprintf("https://internetdb.shodan.io/%s", ipAddress))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result InternetDBResponse
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

func queryIpinfo(ipAddress string) (*IpinfoResponse, error) {
	apiKey := os.Getenv("IPINFO_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("IPINFO_API_KEY environment variable is not set")
	}

	client := &http.Client{}
	req, err := http.NewRequest("GET", fmt.Sprintf("https://ipinfo.io/%s", ipAddress), nil)
	if err != nil {
		return nil, err
	}

	q := req.URL.Query()
	q.Add("token", apiKey)
	req.URL.RawQuery = q.Encode()

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result IpinfoResponse
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}
