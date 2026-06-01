// Copyright 2026 Google LLC
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

package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"flag"

	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	log "github.com/golang/glog"

	"github.com/openconfig/bootz/dhcp"
	dhcpsut "github.com/openconfig/bootz/dhcp/sutserver"
	"github.com/openconfig/bootz/http"
	httpsut "github.com/openconfig/bootz/http/sutserver"
	"github.com/openconfig/bootz/server"
	"github.com/openconfig/bootz/server/controller"
	"github.com/openconfig/bootz/server/entitymanager"
	artifacts "github.com/openconfig/bootz/testdata"
)

var (
	// Bootz server flags
	bootzAddr       = flag.String("bootz_addr", ":15006", "The [ip:]port to start the Bootz
 server.")
	bootzSutAddr    = flag.String("bootz_sut_addr", ":4003", "The [ip:]port to start the Bo
otzController SUT gRPC server.")
	inventoryConfig = flag.String("inv_config", "../../testdata/inventory_local.prototxt", 
"Devices' config files to be loaded by inventory manager")
	generateOVsFor  = flag.String("generate_ovs_for", "123A,123B", "Comma-separated list of
 control card serial numbers to generate OVs for.")
	vendorCACert    = flag.String("vendor_ca_cert", "../../testdata/vendor_ca_cert.txt", "V
endor CA certificate file.")
	vendorCAKey     = flag.String("vendor_ca_key", "../../testdata/vendor_ca_key.txt", "Ven
dor CA private key file.")

	// DHCP flags
	dhcpIntf    = flag.String("dhcp_intf", "", "Network interface to use for DHCP server. I
f empty, standard DHCP server won't start.")
	dhcpSutAddr = flag.String("dhcp_sut_addr", ":4001", "The [ip:]port to start the DHCP SU
T gRPC server.")
	dhcpRecords = flag.String("dhcp_records", "", "Initial list of DHCP records separated b
y a semi-colon (format: mac,ip/mask,gw).")
	dhcpDns     = flag.String("dhcp_dns", "8.8.8.8", "List of DNS servers separated by a se
mi-colon.")

	// HTTP flags
	httpAddr      = flag.String("http_addr", ":80", "The address 'IP:port' to use for HTTP 
server.")
	httpFolder    = flag.String("http_folder", "/www", "The local folder to serve files fro
m.")
	httpSutAddr   = flag.String("http_sut_addr", ":4002", "The [ip:]port to start the HTTP 
SUT gRPC server.")
	httpPublicURL = flag.String("http_public_url", "http://bootz-http", "The public URL of 
this HTTP server that the DUT can access.")
	healthcheck   = flag.Bool("healthcheck", false, "Run healthcheck for all SUT services a
nd exit.")
)

func main() {
	flag.Parse()

	if *healthcheck {
		runHealthcheck()
		return
	}

	log.Infof("============================================================================
=")
	log.Infof("========================= Monolithic SUT Emulator ==========================
=")
	log.Infof("============================================================================
=")

	// 1. Load Security Artifacts
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
		log.Exitf("Failed to generate security artifacts: %v", err)
	}

	// 2. Initialize Entity Manager
	em, err := entitymanager.New(*inventoryConfig, sa)
	if err != nil {
		log.Exitf("unable to initiate inventory manager: %v", err)
	}

	// 3. Start Bootz Server (device-facing)
	bootzServer, err := server.NewServer(*bootzAddr, em, sa)
	if err != nil {
		log.Exitf("Failed to create Bootz server: %v", err)
	}
	go func() {
		if err := bootzServer.Start(); err != nil {
			log.Errorf("Bootz server failed: %v", err)
		}
	}()
	log.Infof("Bootz server started on %s", *bootzAddr)

	// 4. Start Bootz Controller (test-facing)
	bootzURL := *bootzAddr
	if strings.HasPrefix(bootzURL, ":") {
		bootzURL = "bootz://bootz-server" + bootzURL // Default hostname in k8s
	} else {
		bootzURL = "bootz://" + bootzURL
	}
	controllerServer := controller.New(bootzURL)
	if err := controllerServer.Start(*bootzSutAddr); err != nil {
		log.Exitf("Failed to start BootzController SUT server: %v", err)
	}

	// Link them!
	bootzServer.SetNotifyFn(controllerServer.NotifyEvent)
	log.Infof("Linked Bootz server and Controller")

	// 5. Start DHCP SUT Server and optionally DHCP server
	dhcpSutServer := dhcpsut.New()
	if err := dhcpSutServer.Start(*dhcpSutAddr); err != nil {
		log.Exitf("Failed to start DHCP SUT server: %v", err)
	}

	if *dhcpIntf != "" {
		addressMap := make(map[string]*dhcp.Entry)
		if *dhcpRecords != "" {
			for _, r := range strings.Split(*dhcpRecords, ";") {
				parts := strings.Split(r, ",")
				if len(parts) >= 2 {
					e := &dhcp.Entry{IP: parts[1]}
					if len(parts) > 2 {
						e.Gw = parts[2]
					}
					addressMap[parts[0]] = e
				}
			}
		}
		dhcpConf := &dhcp.Config{
			Interface:  *dhcpIntf,
			DNS:        strings.Split(*dhcpDns, ";"),
			AddressMap: addressMap,
			BootzURLs:  []string{bootzURL},
		}
		if err := dhcp.Start(dhcpConf); err != nil {
			log.Errorf("Failed to start DHCP server: %v", err)
		} else {
			log.Infof("DHCP server started on %s", *dhcpIntf)
		}
	}

	// 6. Start HTTP SUT Server and HTTP server
	httpSutServer := httpsut.New(*httpFolder, *httpPublicURL)
	if err := httpSutServer.Start(*httpSutAddr); err != nil {
		log.Exitf("Failed to start HTTP SUT server: %v", err)
	}

	httpConf := &http.Config{
		Address: *httpAddr,
		Folder:  *httpFolder,
	}
	if err := http.Start(httpConf); err != nil {
		log.Errorf("Failed to start HTTP server: %v", err)
	} else {
		log.Infof("HTTP server started on %s", *httpAddr)
	}

	// 7. Wait for shutdown signal
	sigchan := make(chan os.Signal, 1)
	signal.Notify(sigchan, syscall.SIGINT, syscall.SIGTERM)
	<-sigchan
	log.Infof("Shutting down SUT emulator...")

	// Stop all servers
	bootzServer.Stop()
	controllerServer.Stop()
	dhcpSutServer.Stop()
	if *dhcpIntf != "" {
		dhcp.Stop()
	}
	httpSutServer.Stop()
	http.Stop()

	log.Infof("SUT emulator shut down successfully")
}

func runHealthcheck() {
	targets := []struct {
		name string
		addr string
	}{
		{"Bootz Secure", *bootzAddr},
		{"Bootz Controller SUT", *bootzSutAddr},
		{"DHCP SUT", *dhcpSutAddr},
		{"HTTP SUT", *httpSutAddr},
		{"HTTP File Server", *httpAddr},
	}

	failed := false
	for _, t := range targets {
		addr := t.addr
		if strings.HasPrefix(addr, ":") {
			addr = "127.0.0.1" + addr
		}
		conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
		if err != nil {
			log.Errorf("Healthcheck failed for %s (%s): %v", t.name, addr, err)
			failed = true
		} else {
			conn.Close()
		}
	}

	if failed {
		os.Exit(1)
	}
	log.Infof("All SUT services are healthy!")
	os.Exit(0)
}
