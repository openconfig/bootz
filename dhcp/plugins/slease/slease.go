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

// Package slease implements a dhcp server plugin for IP address assignment based.
package slease

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/logger"
	"github.com/coredhcp/coredhcp/plugins"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
)

var log = logger.GetLogger("plugins/slease")

var Plugin = plugins.Plugin{
	Name:   "slease",
	Setup4: setup4,
	Setup6: setup6,
}

type ipv4Entry struct {
	ip      net.IP
	netmask net.IPMask
	gateway net.IP
}

var ipv4Records = map[string]*ipv4Entry{}
var ipv6Records = map[string]net.IP{}
var muRw sync.RWMutex
var ipv4Assigned = map[string]net.IP{}
var ipv6Assigned = map[string]net.IP{}

func setup4(args ...string) (handler.Handler4, error) {
	for _, r := range args {
		if k, r, err := parseRecord4(r); err == nil {
			ipv4Records[k] = r
			log.Debugf("Added ipv4 record: %v, %v, %v, %v", k, r.ip, r.netmask, r.gateway)
		} else {
			return nil, err
		}
	}
	return handler4, nil
}

func setup6(args ...string) (handler.Handler6, error) {
	for _, r := range args {
		if k, r, err := parseRecord6(r); err == nil {
			ipv6Records[k] = r
			log.Debugf("Added ipv6 record: %v, %v", k, r.String())
		} else {
			return nil, err
		}
	}
	return handler6, nil
}

// CleanLog cleans the log of assigned ip. This is only added to help with testing bootz and not recommend for other cases.
func CleanLog() {
	muRw.Lock()
	defer muRw.Unlock()
	ipv4Assigned = map[string]net.IP{}
	ipv6Assigned = map[string]net.IP{}
}

// AssignedIP returns the assigned ip related to hwAddr (mac or serial)
func AssignedIP(hwAddr string) string {
	muRw.RLock()
	defer muRw.RUnlock()
	ipv4, ok := ipv4Assigned[hwAddr]
	if ok {
		return ipv4.String()
	}
	ipv6, ok := ipv6Assigned[hwAddr]
	if ok {
		return ipv6.String()
	}
	return ""
}

func handler4(req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	muRw.Lock()
	defer muRw.Unlock()
	if e, ok := ipv4Records[req.ClientHWAddr.String()]; ok {
		resp4(e, resp)
		ipv4Assigned[req.ClientHWAddr.String()] = resp.ServerIPAddr
	} else if req.Options.Has(dhcpv4.OptionClientIdentifier) {
		cid := req.GetOneOption(dhcpv4.OptionClientIdentifier)
		if e, ok := ipv4Records[toString(cid)]; ok {
			resp4(e, resp)
			ipv4Assigned[toString(cid)] = resp.ServerIPAddr
		}
	}
	return resp, false
}

func resp4(e *ipv4Entry, resp *dhcpv4.DHCPv4) {
	resp.YourIPAddr = e.ip
	resp.Options.Update(dhcpv4.OptSubnetMask(e.netmask))
	resp.Options.Update(dhcpv4.OptRouter(e.gateway))
}

func handler6(req, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
	muRw.Lock()
	defer muRw.Unlock()
	m, err := req.GetInnerMessage()
	if err != nil {
		log.Errorf("Could not decapsulate request: %v", err)
		return nil, true
	}

	if m.Options.OneIANA() == nil {
		return resp, false
	}

	if mac, err := dhcpv6.ExtractMAC(req); err == nil {
		if ip, ok := ipv6Records[mac.String()]; ok {
			resp.AddOption(createIpv6LeaseOption(m, ip))
			ipv6Assigned[mac.String()] = ip
		}
	} else {
		duid := m.Options.ClientID()
		if en, ok := duid.(*dhcpv6.DUIDEN); ok {
			ei := en.EnterpriseIdentifier[:len(en.EnterpriseIdentifier)]
			if ip, ok := ipv6Records[toString(ei)]; ok {
				resp.AddOption(createIpv6LeaseOption(m, ip))
				ipv6Assigned[toString(ei)] = ip
			}
		}
	}
	return resp, false
}

func createIpv6LeaseOption(m *dhcpv6.Message, ip net.IP) *dhcpv6.OptIANA {
	return &dhcpv6.OptIANA{
		IaId: m.Options.OneIANA().IaId,
		Options: dhcpv6.IdentityOptions{Options: []dhcpv6.Option{
			&dhcpv6.OptIAAddress{
				IPv6Addr:          ip,
				PreferredLifetime: 3600 * time.Second,
				ValidLifetime:     3600 * time.Second,
			},
		}},
	}
}

func toString(b []byte) string {
	return strings.TrimFunc(string(b), func(r rune) bool {
		return !unicode.IsGraphic(r)
	})
}

func parseRecord4(r string) (string, *ipv4Entry, error) {
	//format: mac|serial,ipv4/mask,gw
	parts := strings.Split(r, ",")
	if len(parts) != 3 {
		return "", nil, fmt.Errorf("invalid entry %v", r)
	}
	ip, ipNet, err := net.ParseCIDR(parts[1])
	if err != nil {
		return "", nil, fmt.Errorf("invalid ip address %v", parts[1])
	}
	gw := net.ParseIP(parts[2])
	if gw == nil {
		return "", nil, fmt.Errorf("invalid gw address %v", parts[2])
	}

	return parts[0], &ipv4Entry{
		ip:      ip,
		netmask: ipNet.Mask,
		gateway: gw,
	}, nil
}

func parseRecord6(r string) (string, net.IP, error) {
	//format: mac|serial,ipv6
	parts := strings.Split(r, ",")
	if len(parts) != 2 {
		return "", nil, fmt.Errorf("invalid entry %v", r)
	}
	ip, _, err := net.ParseCIDR(parts[1])
	if err != nil {
		return "", nil, fmt.Errorf("invalid ip address %v", parts[1])
	}
	return parts[0], ip, nil
}
