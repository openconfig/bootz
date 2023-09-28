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
// provding your own implementation of the entity manager.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	log "github.com/golang/glog"
	"github.com/openconfig/bootz/dhcp"
	"github.com/openconfig/bootz/server/entitymanager"
	"github.com/openconfig/bootz/server/service"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	bpb "github.com/openconfig/bootz/proto/bootz"
)

var (
	port              = flag.String("port", "15006", "The port to start the Bootz server on localhost")
	dhcpIntf          = flag.String("dhcp_intf", "", "Network interface to use for dhcp server.")
	artifactDirectory = flag.String("artifact_dir", "../testdata/", "The relative directory to look into for certificates, private keys and OVs.")
	inventoryConfig   = flag.String("inv_config", "../testdata/inventory_local.prototxt", "Devices' config files to be loaded by inventory manager")
)

type server struct {
	serv *grpc.Server
	lis  net.Listener
}

// readKeyPair reads the cert/key pair from the specified artifacts directory.
// Certs must have the format {name}_pub.pem and keys must have the format {name}_priv.pem
func readKeypair(name string) (*service.KeyPair, error) {
	cert, err := os.ReadFile(filepath.Join(*artifactDirectory, fmt.Sprintf("%v_pub.pem", name)))
	if err != nil {
		return nil, fmt.Errorf("unable to read %v cert: %v", name, err)
	}
	key, err := os.ReadFile(filepath.Join(*artifactDirectory, fmt.Sprintf("%v_priv.pem", name)))
	if err != nil {
		return nil, fmt.Errorf("unable to read %v key: %v", name, err)
	}
	return &service.KeyPair{
		Cert: string(cert),
		Key:  string(key),
	}, nil
}

// readOVs discovers and reads all available OVs in the artifacts directory.
func readOVs() (service.OVList, error) {
	ovs := make(service.OVList)
	files, err := os.ReadDir(*artifactDirectory)
	if err != nil {
		return nil, fmt.Errorf("unable to list files in artifact directory: %v", err)
	}
	for _, f := range files {
		if strings.HasPrefix(f.Name(), "ov") {
			bytes, err := os.ReadFile(filepath.Join(*artifactDirectory, f.Name()))
			if err != nil {
				return nil, err
			}
			trimmed := strings.TrimPrefix(f.Name(), "ov_")
			trimmed = strings.TrimSuffix(trimmed, ".txt")
			ovs[trimmed] = string(bytes)
		}
	}
	if len(ovs) == 0 {
		return nil, fmt.Errorf("found no OVs in artifacts directory")
	}
	return ovs, err
}

// generateServerTLSCert creates a new TLS keypair from the PDC.
func generateServerTLSCert(pdc *service.KeyPair) (*tls.Certificate, error) {
	tlsCert, err := tls.X509KeyPair([]byte(pdc.Cert), []byte(pdc.Key))
	if err != nil {
		return nil, fmt.Errorf("unable to generate Server TLS Certificate from PDC %v", err)
	}
	return &tlsCert, err
}

// parseSecurityArtifacts reads from the specified directory to find the required keypairs and ownership vouchers.
func parseSecurityArtifacts() (*service.SecurityArtifacts, error) {
	oc, err := readKeypair("oc")
	if err != nil {
		return nil, err
	}
	pdc, err := readKeypair("pdc")
	if err != nil {
		return nil, err
	}
	vendorCA, err := readKeypair("vendorca")
	if err != nil {
		return nil, err
	}
	ovs, err := readOVs()
	if err != nil {
		return nil, err
	}
	tlsCert, err := generateServerTLSCert(pdc)
	if err != nil {
		return nil, err
	}
	return &service.SecurityArtifacts{
		OC:         oc,
		PDC:        pdc,
		VendorCA:   vendorCA,
		OV:         ovs,
		TLSKeypair: tlsCert,
	}, nil
}

func (s *server) Start() error {
	return s.serv.Serve(s.lis)
}

func (s *server) Stop() {
	s.serv.Stop()
}

// newServer creates a new Bootz gRPC server from flags.
func newServer() (*server, error) {
	if *port == "" {
		return nil, fmt.Errorf("no port selected. specify with the --port flag")
	}
	if *artifactDirectory == "" {
		return nil, fmt.Errorf("no artifact directory selected. specify with the --artifact_dir flag")
	}

	log.Infof("Setting up server security artifacts: OC, OVs, PDC, VendorCA")
	sa, err := parseSecurityArtifacts()
	if err != nil {
		return nil, err
	}

	log.Infof("Setting up entities")
	em, err := entitymanager.New(*inventoryConfig)
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
	if !trustBundle.AppendCertsFromPEM([]byte(sa.PDC.Cert)) {
		return nil, fmt.Errorf("unable to add PDC cert to trust pool")
	}
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
