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

// Package bootz implements a dhcp server plugin to advertise the bootz server address.
package bootz

import (
	"encoding/binary"
	"fmt"
	"net/url"

	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/logger"
	"github.com/coredhcp/coredhcp/plugins"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
)

var log = logger.GetLogger("plugins/bootz")

var Plugin = plugins.Plugin{
	Name:   "bootz",
	Setup4: setup4,
	Setup6: setup6,
}

const (
	OPTION_V4_SZTP_REDIRECT uint8 = 143
	OPTION_V6_SZTP_REDIRECT uint8 = 136
)

var (
	ztpV4Opt *dhcpv4.Option
	ztpV6Opt dhcpv6.Option
)

func encodeBootstrapServerList(urls []string) []byte {
	// From RFC 8572 section 8.3:
	//
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...-+-+-+-+-+-+-+
	// |       uri-length              |          URI                  |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...-+-+-+-+-+-+-+
	//
	// * uri-length: 2 octets long; specifies the length of the URI data.
	// * URI: URI of the SZTP bootstrap server.
	b := []byte{}
	for _, u := range urls {
		b = binary.BigEndian.AppendUint16(b, uint16(len(u)))
		b = append(b, []byte(u)...)
	}
	return b
}

// Verifies that the passed Bootz servers are valid URLs and returns them as a list of strings.
func parseArgs(args ...string) ([]string, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("at least one argument must be passed to BootZ plugin, got %d", len(args))
	}
	urls := make([]string, len(args))
	for i, arg := range args {
		u, err := url.Parse(arg)
		if err != nil {
			return nil, err
		}
		urls[i] = u.String()
	}
	return urls, nil
}

func setup4(args ...string) (handler.Handler4, error) {
	urls, err := parseArgs(args...)
	if err != nil {
		return nil, err
	}

	ztpV4Opt = &dhcpv4.Option{
		Code:  dhcpv4.GenericOptionCode(OPTION_V4_SZTP_REDIRECT),
		Value: dhcpv4.String(string(encodeBootstrapServerList(urls))),
	}
	return handler4, nil
}

func setup6(args ...string) (handler.Handler6, error) {
	urls, err := parseArgs(args...)
	if err != nil {
		return nil, err
	}
	ztpV6Opt = &dhcpv6.OptionGeneric{
		OptionCode: dhcpv6.OptionCode(OPTION_V6_SZTP_REDIRECT),
		OptionData: encodeBootstrapServerList(urls),
	}
	return handler6, nil
}

func handler4(req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	for _, p := range req.ParameterRequestList() {
		if p.Code() == OPTION_V4_SZTP_REDIRECT {
			resp.Options.Update(*ztpV4Opt)
			log.Debugf("Added ZTP option: %v", resp.Summary())
			break
		}
	}
	return resp, false
}

func handler6(req, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
	decap, err := req.GetInnerMessage()
	if err != nil {
		log.Errorf("Could not decapsulate request: %v", err)
		return nil, false
	}

	for _, code := range decap.Options.RequestedOptions() {
		if code == ztpV6Opt.Code() {
			resp.AddOption(ztpV6Opt)
			log.Debugf("Added ZTP option: %v", resp.Summary())
		}
	}
	return resp, false
}
