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

	"github.com/coredhcp/coredhcp/logger"

	cdconfig "github.com/coredhcp/coredhcp/config"
	cdplugins "github.com/coredhcp/coredhcp/plugins"
	plDNS "github.com/coredhcp/coredhcp/plugins/dns"
	plleasetime "github.com/coredhcp/coredhcp/plugins/leasetime"
	plserverid "github.com/coredhcp/coredhcp/plugins/serverid"
	cdserver "github.com/coredhcp/coredhcp/server"
	plbootz "github.com/openconfig/bootz/dhcp/plugins/bootz"
	plslease "github.com/openconfig/bootz/dhcp/plugins/slease"

	cpb "github.com/openconfig/bootz/dhcp/proto/config"
)

const confTemplate = `
# CoreDHCP configuration (yaml)
server6:
   plugins:
     - server_id: LL {{ .IntfMacAddr }}
     {{ if .BootzURLs }}
     - bootz: {{ .BootzURLs }}
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
    {{ if .BootzURLs }}
    - bootz: {{ .BootzURLs }}
    {{ end }}
    {{ if .DNSv4 }}
    - DNS: {{ .DNSv4 }}
    {{ end }}
    {{ if .IPv4Leases }}
    - slease: {{ .IPv4Leases }}
    {{ end }}
`

type Server struct {
	server *cdserver.Servers
}

var instance *Server = nil
var lock = &sync.Mutex{}
var log = logger.GetLogger("bootz/dhcp")

var desiredPlugins = []*cdplugins.Plugin{
	&plserverid.Plugin,
	&plleasetime.Plugin,
	&plDNS.Plugin,
	&plbootz.Plugin,
	&plslease.Plugin,
}

func init() {
	for _, plugin := range desiredPlugins {
		if err := cdplugins.RegisterPlugin(plugin); err != nil {
			log.Fatalf("Failed to register plugin '%s': %v", plugin.Name, err)
		}
	}
}

// Start starts the dhcp server with the given configuration.
func Start(conf *cpb.Config) error {
	lock.Lock()
	defer lock.Unlock()

	if instance != nil {
		return fmt.Errorf("dhcp server already started")
	}

	configFile, err := generateConfigFile(conf)
	if err != nil {
		return err
	}
	defer os.Remove(configFile)

	c, err := cdconfig.Load(configFile)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %v", err)
	}

	srv, err := cdserver.Start(c)
	if err != nil {
		return fmt.Errorf("error starting DHCP server: %v", err)
	}

	instance = &Server{
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

func generateConfigFile(conf *cpb.Config) (string, error) {
	configFile, err := os.CreateTemp("", "coredhcp_conf_*.yml")
	if err != nil {
		return "", fmt.Errorf("error creating configuration file: %v", err)
	}

	confTmpl, err := template.New("coredhcp").Parse(confTemplate)
	if err != nil {
		return "", fmt.Errorf("error parsing configuration template: %v", err)
	}

	intf, err := net.InterfaceByName(conf.GetInterface())
	if err != nil {
		return "", fmt.Errorf("unknown interface %v: %v", conf.GetInterface(), err)
	}
	log.Infof("%v", intf.HardwareAddr.String())

	IPv4Addr := getIPv4Address(intf)
	if IPv4Addr == nil {
		return "", fmt.Errorf("unable to find IPv4 address for interface %v", conf.GetInterface())
	}

	DNSv4, DNSv6 := []string{}, []string{}
	for _, v := range conf.GetDns() {
		if isIPv6(v) {
			DNSv6 = append(DNSv6, v)
		} else {
			DNSv4 = append(DNSv4, v)
		}
	}

	v6Records, v4Records := []string{}, []string{}
	for _, v := range conf.GetRecords() {
		if isIPv6(v.GetIp()) {
			v6Records = append(v6Records, fmt.Sprintf("%s,%s", v.GetMachine(), v.GetIp()))
		} else {
			v4Records = append(v4Records, fmt.Sprintf("%s,%s,%s", v.GetMachine(), v.GetIp(), v.GetGateway()))
		}
	}

	if err := confTmpl.Execute(configFile, struct {
		IntfIPAddr  string
		IntfMacAddr string
		DNSv4       string
		DNSv6       string
		IPv4Leases  string
		IPv6Leases  string
		BootzURLs   string
	}{
		IntfIPAddr:  IPv4Addr.String(),
		IntfMacAddr: intf.HardwareAddr.String(),
		DNSv4:       strings.Join(DNSv4, " "),
		DNSv6:       strings.Join(DNSv6, " "),
		IPv4Leases:  strings.Join(v4Records, " "),
		IPv6Leases:  strings.Join(v6Records, " "),
		BootzURLs:   strings.Join(conf.GetBootzUrls(), " "),
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
