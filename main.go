package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"github.com/fatih/color"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

var (
	titleColor   = color.New(color.FgHiCyan, color.Bold)
	infoColor    = color.New(color.FgHiGreen)
	warningColor = color.New(color.FgHiYellow)
	errorColor   = color.New(color.FgHiRed)
	keyColor     = color.New(color.FgHiBlue)
	valueColor   = color.New(color.FgHiWhite)
)

func main() {
	if len(os.Args) < 2 {
		warningColor.Println("Usage: ip <ip address> [options:-n(nmap),-m(masscan),-s(internetdb)/default:-s]")
		os.Exit(1)
	}

	ipAddress := os.Args[1]
	option := "-s" // Default option

	if len(os.Args) > 2 {
		option = os.Args[2]
	}
	runIpinfo(ipAddress)

	switch option {
	case "-n":
		runNmap(ipAddress, os.Args[3:])
	case "-ma":
		runMasscan(ipAddress)
	case "-s", "":
		runInternetDB(ipAddress)
	case "-m":
		runMc(ipAddress)
	default:
		warningColor.Println("Invalid option. Using default option (-s for internetdb).")
		runInternetDB(ipAddress)
	}
}

type NmapRun struct {
	XMLName xml.Name `xml:"nmaprun"`
	Hosts   []Host   `xml:"host"`
}

type Host struct {
	Addresses []Address `xml:"address"`
	Ports     []Port    `xml:"ports>port"`
}

type Address struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type Port struct {
	Protocol string  `xml:"protocol,attr"`
	PortID   string  `xml:"portid,attr"`
	State    State   `xml:"state"`
	Service  Service `xml:"service"`
}

type State struct {
	State string `xml:"state,attr"`
}

type Service struct {
	Name string `xml:"name,attr"`
}

func runNmap(ipAddress string, args []string) {
	titleColor.Println("Running nmap...")
	cmdArgs := append([]string{"--top-ports", "1000", "-T4", "-Pn", "-oX", "-"}, ipAddress)
	cmdArgs = append(cmdArgs, args...)
	cmd := exec.Command("nmap", cmdArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		errorColor.Printf("nmap command failed: %s\n", err)
		fmt.Println("nmap output:", string(output))
		return
	}

	var nmapRun NmapRun
	err = xml.Unmarshal(output, &nmapRun)
	if err != nil {
		errorColor.Printf("Failed to parse nmap output: %s\n", err)
		return
	}

	for _, host := range nmapRun.Hosts {
		if len(host.Ports) > 0 {
			for _, port := range host.Ports {
				if port.State.State == "open" {
					keyColor.Printf("  %s/%s", port.PortID, port.Protocol)
					valueColor.Printf(" - %s\n", port.Service.Name)
				}
			}
		} else {
			warningColor.Println("No open ports found")
		}
	}
}

func runMc(ipAddress string) {
	//call api https://api.mcstatus.io/v2/status/java/<address>
	titleColor.Println("Running mc...")
	url := "https://api.mcstatus.io/v2/status/java/" + ipAddress
	//call api with http.Get
	resp, err := http.Get(url)

	if err != nil {
		errorColor.Printf("mc command failed: %s\n", err)
		return
	}

	defer resp.Body.Close()

	//parse the response
	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		errorColor.Printf("Failed to parse mc output: %s\n", err)
		return
	}

	//print the result
	verson, ok := result["version"].(map[string]interface{})
	if !ok {
		errorColor.Println("Failed to parse version information")
		return
	}
	printKeyValue("Version", fmt.Sprintf("%v", verson["name_clean"]))
	players, ok := result["players"].(map[string]interface{})
	if !ok {
		errorColor.Println("Failed to parse players information")
		return
	}
	printKeyValue("Players", fmt.Sprintf("%v/%v", players["online"], players["max"]))
	motd, ok := result["motd"].(map[string]interface{})
	if !ok {
		errorColor.Println("Failed to parse motd information")
		return
	}
	printKeyValue("MOTD", fmt.Sprintf("%v", motd["clean"]))

}
func runMasscan(ipAddress string) {
	titleColor.Println("Running masscan...")
	cmd := exec.Command("masscan", ipAddress, "--rate", "1000", "-p0-65535")
	output, err := cmd.CombinedOutput()
	if err != nil {
		errorColor.Printf("masscan command failed: %s\n", err)
		fmt.Println("masscan output:", string(output))
		return
	}
	fmt.Println(string(output))
}

func runInternetDB(ipAddress string) {
	titleColor.Println("Querying...")
	result, err := queryInternetDB(ipAddress)
	if err != nil {
		errorColor.Printf("InternetDB query failed: %s\n", err)
		return
	}
	printKeyValue("IP", result.IP)
	printKeyValue("Hostnames", strings.Join(result.Hostnames, ", "))
	printKeyValue("Ports", fmt.Sprintf("%v", result.Ports))
	printKeyValue("Tags", strings.Join(result.Tags, ", "))
	printKeyValue("Vulnerabilities", strings.Join(result.Vulns, ", "))
	printKeyValue("CPEs", strings.Join(result.CPEs, ", "))
}

func runIpinfo(ipAddress string) {
	titleColor.Println(ipAddress)
	result, err := queryIpinfo(ipAddress)
	if err != nil {
		if err.Error() == "IPINFO_API_KEY environment variable is not set" {
			errorColor.Println("Error: IPINFO_API_KEY is not set.")
			warningColor.Println("Please set the IPINFO_API_KEY environment variable:")
			fmt.Println("  For Bash (Linux/macOS):")
			fmt.Println("    export IPINFO_API_KEY=your_api_key_here")
			fmt.Println("  For Command Prompt (Windows):")
			fmt.Println("    set IPINFO_API_KEY=your_api_key_here")
			fmt.Println("  For PowerShell (Windows):")
			fmt.Println("    $env:IPINFO_API_KEY=\"your_api_key_here\"")
			return
		}
		errorColor.Printf("ipinfo query failed: %s\n", err)
		return
	}
	printKeyValue("Country", result.Country)
	printKeyValue("Organization", result.Org)
}

func printKeyValue(key, value string) {
	keyColor.Printf("%s: ", key)
	valueColor.Println(value)
}
