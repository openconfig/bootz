// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package dhcp implements a DHCP server for IP address assignment and bootz server advertisement.
package dhcp

import (
	"fmt"
	"html/template"
	"net"
	"os"
	"strings"
	"sync"

	cdconfig "github.com/coredhcp/coredhcp/config"
	cdplugins "github.com/coredhcp/coredhcp/plugins"
	cdserver "github.com/coredhcp/coredhcp/server"

	plDNS "github.com/coredhcp/coredhcp/plugins/dns"
	plleasetime "github.com/coredhcp/coredhcp/plugins/leasetime"
	plserverid "github.com/coredhcp/coredhcp/plugins/serverid"
	plbootz "github.com/openconfig/bootz/dhcp/plugins/bootz"
	plslease "github.com/openconfig/bootz/dhcp/plugins/slease"
)

const confTemplate = `
# CoreDHCP configuration (yaml)
server6:
   plugins:
     - server_id: LL {{ .IntfMacAddr }}
     {{ if .BootzURL }}
     - bootz: {{ .BootzURL }}
     {{ end }}
     {{ if .DNSv6 }}
     - DNS: {{ .DNSv6 }}
     {{ end }}
     {{ if .IPv6Leases }}
     - slease: {{ .IPv6Leases }}
     {{ end }}
server4:
  plugins:
    - lease_time: 3600s
    - server_id: {{ .IntfIPAddr }}
    {{ if .BootzURL }}
    - bootz: {{ .BootzURL }}
    {{ end }}
    {{ if .DNSv4 }}
    - DNS: {{ .DNSv4 }}
    {{ end }}
    {{ if .IPv4Leases }}
    - slease: {{ .IPv4Leases }}
    {{ end }}
`

var desiredPlugins = []*cdplugins.Plugin{
	&plserverid.Plugin,
	&plleasetime.Plugin,
	&plDNS.Plugin,
	&plbootz.Plugin,
	&plslease.Plugin,
}

// Config contains the dhcp server configuration.
type Config struct {
	Interface  string
	DNS        []string
	AddressMap map[string]*Entry
	BootzURL   string
}

// Entry represents a dhcp record.
type Entry struct {
	IP string
	Gw string
}

type DHCPServerStatus string

type Server struct {
	server *cdserver.Servers
	status DHCPServerStatus
}

const (
	DHCPServerStatus_UNINITIALIZED DHCPServerStatus = "Uninitialized"
	DHCPServerStatus_RUNNING       DHCPServerStatus = "Running"
	DHCPServerStatus_FAILURE       DHCPServerStatus = "Failure"
	DHCPServerStatus_EXITED        DHCPServerStatus = "Exited"
)

var instance *Server = &Server{status: DHCPServerStatus_UNINITIALIZED}
var lock = &sync.Mutex{}

// Start starts the dhcp server with the given configuration.
func Start(conf *Config) (DHCPServerStatus, error) {
	lock.Lock()
	defer lock.Unlock()

	instance = &Server{}

	if instance.status == DHCPServerStatus_RUNNING {
		return instance.status, fmt.Errorf("dhcp server already started")
	}

	configFile, err := generateConfigFile(conf)
	if err != nil {
		instance.status = DHCPServerStatus_FAILURE
		return instance.status, err
	}

	c, err := cdconfig.Load(configFile)
	if err != nil {
		instance.status = DHCPServerStatus_FAILURE
		return instance.status, fmt.Errorf("failed to load configuration: %v", err)
	}

	for _, plugin := range desiredPlugins {
		if err := cdplugins.RegisterPlugin(plugin); err != nil {
			instance.status = DHCPServerStatus_FAILURE
			return instance.status, fmt.Errorf("failed to register plugin '%s': %v", plugin.Name, err)
		}
	}

	srv, err := cdserver.Start(c)
	if err != nil {
		instance.status = DHCPServerStatus_FAILURE
		return instance.status, fmt.Errorf("error starting DHCP server: %v", err)
	}
	os.Remove(configFile)

	instance.server = srv
	instance.status = DHCPServerStatus_RUNNING
	return instance.status, nil
}

// Stop stops the DHCP server.
func Stop() DHCPServerStatus {
	lock.Lock()
	defer lock.Unlock()
	if instance != nil {
		instance.server.Close()
		instance.server.Wait()
	}
	instance.status = DHCPServerStatus_EXITED
	return instance.status
}

func Status() DHCPServerStatus {
	return instance.status
}

func generateConfigFile(conf *Config) (string, error) {
	configFile, err := os.CreateTemp("", "coredhcp_conf_*.yml")
	if err != nil {
		return "", fmt.Errorf("error creating configuration file: %v", err)
	}

	confTmpl, err := template.New("coredhcp").Parse(confTemplate)
	if err != nil {
		return "", fmt.Errorf("error parsing configuration template: %v", err)
	}

	intf, err := net.InterfaceByName(conf.Interface)
	if err != nil {
		return "", fmt.Errorf("unknown interface %v", conf.Interface)
	}

	IPv4Addr := getIPv4Address(intf)
	if IPv4Addr == nil {
		return "", fmt.Errorf("unable to find IPv4 address for interface %v", conf.Interface)
	}

	DNSv4, DNSv6 := []string{}, []string{}
	for _, v := range conf.DNS {
		if isIPv6(v) {
			DNSv6 = append(DNSv6, v)
		} else {
			DNSv4 = append(DNSv4, v)
		}
	}

	v6Records, v4Records := []string{}, []string{}
	for k, a := range conf.AddressMap {
		if isIPv6(a.IP) {
			v6Records = append(v6Records, fmt.Sprintf("%s,%s", k, a.IP))
		} else {
			v4Records = append(v4Records, fmt.Sprintf("%s,%s,%s", k, a.IP, a.Gw))
		}
	}

	if err := confTmpl.Execute(configFile, struct {
		IntfIPAddr  string
		IntfMacAddr string
		DNSv4       string
		DNSv6       string
		IPv4Leases  string
		IPv6Leases  string
		BootzURL    string
	}{
		IntfIPAddr:  IPv4Addr.String(),
		IntfMacAddr: intf.HardwareAddr.String(),
		DNSv4:       strings.Join(DNSv4, " "),
		DNSv6:       strings.Join(DNSv6, " "),
		IPv4Leases:  strings.Join(v4Records, " "),
		IPv6Leases:  strings.Join(v6Records, " "),
		BootzURL:    conf.BootzURL,
	}); err != nil {
		return "", fmt.Errorf("error generating configuration template: %v", err)
	}
	return configFile.Name(), nil
}

func isIPv6(address string) bool {
	return strings.Count(address, ":") >= 2
}

func getIPv4Address(i *net.Interface) net.IP {
	if addrs, err := i.Addrs(); err == nil {
		for _, a := range addrs {
			v4 := a.(*net.IPNet).IP.To4()
			if v4 != nil {
				return v4
			}
		}
	}
	return nil
}
