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
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net"
	"strings"

	log "github.com/golang/glog"
	"github.com/openconfig/bootz/dhcp"
	"github.com/openconfig/bootz/server/entitymanager"
	"github.com/openconfig/bootz/server/service"
	artifacts "github.com/openconfig/bootz/testdata"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	bpb "github.com/openconfig/bootz/proto/bootz"
)

var (
	port            = flag.String("port", "15006", "The port to start the Bootz server on localhost")
	dhcpIntf        = flag.String("dhcp_intf", "", "Network interface to use for dhcp server.")
	inventoryConfig = flag.String("inv_config", "../testdata/inventory_local.prototxt", "Devices' config files to be loaded by inventory manager")
	generateOVsFor  = flag.String("generate_ovs_for", "", "Comma-separated list of control card serial numbers to generate OVs for.")
)

type server struct {
	serv *grpc.Server
	lis  net.Listener
}

func (s *server) Start() error {
	return s.serv.Serve(s.lis)
}

func (s *server) Stop() {
	s.serv.GracefulStop()
}

// newServer creates a new Bootz gRPC server from flags.
func newServer() (*server, error) {
	if *port == "" {
		return nil, fmt.Errorf("no port selected. specify with the --port flag")
	}

	log.Infof("Setting up server security artifacts: OC, OVs, PDC, VendorCA")
	serials := strings.Split(*generateOVsFor, ",")

	sa, err := artifacts.GenerateSecurityArtifacts(serials, "Google", "Cisco")
	if err != nil {
		return nil, err
	}

	log.Infof("Setting up entities")
	em, err := entitymanager.New(*inventoryConfig, sa)
	if err != nil {
		return nil, fmt.Errorf("unable to initiate inventory manager %v", err)
	}

	if *dhcpIntf != "" {
		if err := startDhcpServer(em); err != nil {
			return nil, fmt.Errorf("unable to start dhcp server %v", err)
		}
	}

	c := service.New(em)

	trustBundle := x509.NewCertPool()
	trustBundle.AddCert(sa.TrustAnchor)

	tls := &tls.Config{
		Certificates: []tls.Certificate{*sa.TLSKeypair},
		RootCAs:      trustBundle,
	}
	log.Infof("Creating server...")
	s := grpc.NewServer(grpc.Creds(credentials.NewTLS(tls)))
	bpb.RegisterBootstrapServer(s, c)

	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%v", *port))
	if err != nil {
		return nil, fmt.Errorf("error listening on port: %v", err)
	}
	log.Infof("Server ready and listening on %s", lis.Addr())
	log.Infof("=============================================================================")
	return &server{serv: s, lis: lis}, nil
}

func main() {
	flag.Parse()

	log.Infof("=============================================================================")
	log.Infof("=========================== BootZ Server Emulator ===========================")
	log.Infof("=============================================================================")

	s, err := newServer()
	if err != nil {
		log.Exit(err)
	}

	if err := s.Start(); err != nil {
		log.Exit(err)
	}
}

func startDhcpServer(em *entitymanager.InMemoryEntityManager) error {
	conf := &dhcp.Config{
		Interface:  *dhcpIntf,
		AddressMap: make(map[string]*dhcp.Entry),
	}

	for _, c := range em.GetChassisInventory() {
		if dhcpConf := c.GetDhcpConfig(); dhcpConf != nil {
			key := dhcpConf.GetHardwareAddress()
			if key == "" {
				key = c.GetSerialNumber()
			}
			conf.AddressMap[key] = &dhcp.Entry{
				IP: dhcpConf.GetIpAddress(),
				Gw: dhcpConf.GetGateway(),
			}
		}
	}

	return dhcp.Start(conf)
}
