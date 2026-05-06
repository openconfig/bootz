// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Bootz server reference implementation.
//
// The bootz server will provide a simple file based bootstrap
// implementation for devices. The service can be extended by
// providing your own implementation of the entity manager.
package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"strings"

	"github.com/openconfig/bootz/server"
	"github.com/openconfig/bootz/server/entitymanager"

	log "github.com/golang/glog"
	artifacts "github.com/openconfig/bootz/testdata"
)

var (
	bootzAddr       = flag.String("bootz_addr", "15006", "The [ip:]port to start the Bootz server. When ip is not specified, the server starts on localhost")
	dhcpIntf        = flag.String("dhcp_intf", "", "Network interface to use for dhcp server.")
	inventoryConfig = flag.String("inv_config", "../../testdata/inventory_local.prototxt", "Devices' config files to be loaded by inventory manager")
	generateOVsFor  = flag.String("generate_ovs_for", "123A,123B", "Comma-separated list of control card serial numbers to generate OVs for.")
	vendorCACert    = flag.String("vendor_ca_cert", "../../testdata/vendor_ca_cert.txt", "Vendor CA certificate file.")
	vendorCAKey     = flag.String("vendor_ca_key", "../../testdata/vendor_ca_key.txt", "Vendor CA private key file.")
)

// Convert address to localhost when no ip is specified.
func convertAddress(addr string) string {
	items := strings.Split(addr, ":")
	listenAddr := addr
	if len(items) == 1 {
		listenAddr = fmt.Sprintf("localhost:%v", addr)
	}
	return listenAddr
}

func main() {
	flag.Parse()

	if *bootzAddr == "" {
		log.Exit("no address selected. specify with the --addr [ip:]port flag")
	}

	log.Infof("=============================================================================")
	log.Infof("=========================== BootZ Server Emulator ===========================")
	log.Infof("=============================================================================")

	tlsCert, err := tls.LoadX509KeyPair(*vendorCACert, *vendorCAKey)
	if err != nil {
		log.Exitf("Invalid vendor CA cert/key pair: %v.", err)
	}
	cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		log.Exitf("Failed to parse vendor CA cert: %v.", err)
	}
	rsaKey, ok := tlsCert.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		log.Exitf("Failed to parse vendor CA key as an RSA key")
	}

	log.Infof("Setting up server security artifacts: OC, OVs, PDC, VendorCA")
	serials := strings.Split(*generateOVsFor, ",")

	sa, err := artifacts.GenerateSecurityArtifacts(serials, "Google", cert, rsaKey)
	if err != nil {
		log.Exit("err")
	}

	log.Infof("Setting up entities")
	em, err := entitymanager.New(*inventoryConfig, sa)
	if err != nil {
		log.Exit("unable to initiate inventory manager %v", err)
	}

	s, err := server.NewServer(convertAddress(*bootzAddr), em, sa)
	if err != nil {
		log.Exit(err)
	}

	if err := s.Start(); err != nil {
		log.Exit(err)
	}
}
