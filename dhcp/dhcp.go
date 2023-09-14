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

// Package dhcp implements a DHCP server for IP address assignment and bootz server advertisment.
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

	pldns "github.com/coredhcp/coredhcp/plugins/dns"
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
     {{ if .BootzUrl }}
     - bootz: {{ .BootzUrl }}
     {{ end }}
     {{ if .Dnsv6 }}
     - dns: {{ .Dnsv6 }}
     {{ end }}
     {{ if .Ipv6Leases }}
     - slease: {{ .Ipv6Leases }}
     {{ end }}
server4:
  plugins:
    - lease_time: 3600s
    - server_id: {{ .IntfIpAddr }}
    {{ if .BootzUrl }}
    - bootz: {{ .BootzUrl }}
    {{ end }}
    {{ if .Dnsv4 }}
    - dns: {{ .Dnsv4 }}
    {{ end }}
    {{ if .Ipv4Leases }}
    - slease: {{ .Ipv4Leases }}
    {{ end }}
`

var desiredPlugins = []*cdplugins.Plugin{
	&plserverid.Plugin,
	&plleasetime.Plugin,
	&pldns.Plugin,
	&plbootz.Plugin,
	&plslease.Plugin,
}

// DHCPConfig contains the dhcp server configuration.
type DHCPConfig struct {
	Interface  string
	Dns        []string
	AddressMap map[string]*DHCPEntry
	BootzUrl   string
}

// DHCPEntry represents a dhcp record.
type DHCPEntry struct {
	Ip string
	Gw string
}

type dhcpServer struct {
	server *cdserver.Servers
}

var instance *dhcpServer = nil
var lock = &sync.Mutex{}

// Start starts the dhcp server with the given configuration.
func Start(conf *DHCPConfig) error {
	lock.Lock()
	defer lock.Unlock()

	if instance != nil {
		return fmt.Errorf("dhcp server already started")
	}

	configFile, err := generateConfigFile(conf)
	if err != nil {
		return err
	}

	c, err := cdconfig.Load(configFile)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %v", err)
	}

	for _, plugin := range desiredPlugins {
		if err := cdplugins.RegisterPlugin(plugin); err != nil {
			return fmt.Errorf("failed to register plugin '%s': %v", plugin.Name, err)
		}
	}

	srv, err := cdserver.Start(c)
	if err != nil {
		return fmt.Errorf("error starting DHCP server: %v", err)
	}
	os.Remove(configFile)

	instance = &dhcpServer{
		server: srv,
	}
	return nil
}

// Stop stops the DHCP server.
func Stop() {
	lock.Lock()
	defer lock.Unlock()
	if instance != nil {
		instance.server.Close()
		instance.server.Wait()
	}
	instance = nil
}

func generateConfigFile(conf *DHCPConfig) (string, error) {
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
		return "", fmt.Errorf("unknown interface %v", *intf)
	}

	ipv4Addr := getIpv4Address(intf)
	if ipv4Addr == nil {
		return "", fmt.Errorf("unable to find ipv4 address for interface %v", conf.Interface)
	}

	dnsv4, dnsv6 := []string{}, []string{}
	for _, v := range conf.Dns {
		if isIpv6(v) {
			dnsv6 = append(dnsv6, v)
		} else {
			dnsv4 = append(dnsv4, v)
		}
	}

	v6Records, v4Records := []string{}, []string{}
	for k, a := range conf.AddressMap {
		if isIpv6(a.Ip) {
			v6Records = append(v6Records, fmt.Sprintf("%s,%s", k, a.Ip))
		} else {
			v4Records = append(v4Records, fmt.Sprintf("%s,%s,%s", k, a.Ip, a.Gw))
		}
	}

	if err := confTmpl.Execute(configFile, struct {
		IntfIpAddr  string
		IntfMacAddr string
		Dnsv4       string
		Dnsv6       string
		Ipv4Leases  string
		Ipv6Leases  string
		BootzUrl    string
	}{
		IntfIpAddr:  ipv4Addr.String(),
		IntfMacAddr: intf.HardwareAddr.String(),
		Dnsv4:       strings.Join(dnsv4, " "),
		Dnsv6:       strings.Join(dnsv6, " "),
		Ipv4Leases:  strings.Join(v4Records, " "),
		Ipv6Leases:  strings.Join(v6Records, " "),
		BootzUrl:    conf.BootzUrl,
	}); err != nil {
		return "", fmt.Errorf("error generating configuration template: %v", err)
	}
	return configFile.Name(), nil
}

func isIpv6(address string) bool {
	return strings.Count(address, ":") >= 2
}

func getIpv4Address(i *net.Interface) net.IP {
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
