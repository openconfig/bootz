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

// Package main provides the main function for running the DHCP server.
package main

import (
	"flag"
	"os"
	"os/signal"
	"strings"

	log "github.com/golang/glog"
	"github.com/openconfig/bootz/dhcp"
)

var (
	intf    = flag.String("i", "eth7", "Network interface to use for dhcp server.")
	records = flag.String("records", "4c:5d:3c:ef:de:60,5.78.26.27/16,5.78.0.1;FOX2506P2QT,5::10/64", "List of dhcp records separated by a semi-colon.")
	dns     = flag.String("dns", "5.38.4.124", "List of dns servers separated by a semi-colon.")
	bootz   = flag.String("bootz_url", "bootz://dev-mgbl-lnx6.cisco.com:50052/grpc", "Bootz server URL.")
)

func main() {
	flag.Parse()
	if *intf == "" {
		log.Exitf("no interface specified (-i)")
	}

	addressMap := map[string]*dhcp.Entry{}
	for _, r := range strings.Split(*records, ";") {
		parts := strings.Split(r, ",")
		if len(parts) < 2 {
			log.Exitf("incorrect record format: %v", r)
		}
		e := &dhcp.Entry{
			IP: parts[1],
		}
		if len(parts) > 2 {
			e.Gw = parts[2]
		}
		addressMap[parts[0]] = e
	}

	conf := &dhcp.Config{
		Interface:  *intf,
		DNS:        strings.Split(*dns, ";"),
		AddressMap: addressMap,
		BootzURL:   *bootz,
	}

	go func() {
		sigchan := make(chan os.Signal, 1)
		signal.Notify(sigchan, os.Interrupt)
		<-sigchan
		dhcp.Stop()
		os.Exit(0)
	}()

	if _, err := dhcp.Start(conf); err != nil {
		log.Exitf("error starting dhcp server: %v", err)
	}

	select {}
}
