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
package server

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	log "github.com/golang/glog"
	"github.com/openconfig/bootz/dhcp"
	"github.com/openconfig/bootz/server/entitymanager"
	"github.com/openconfig/bootz/server/service"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	bpb "github.com/openconfig/bootz/proto/bootz"
)

var (
	bootzAddress      = flag.String("address", "8008", "The [ip:]port to listen for the bootz request. when ip is not given, the server will listen on localhost.")
	dhcpIntf          = flag.String("dhcp_intf", "", "Network interface to use for dhcp server.")
	artifactDirectory = flag.String("artifact_dir", "../testdata/", "The relative directory to look into for certificates, private keys and OVs.")
	inventoryConfig   = flag.String("inv_config", "../testdata/inventory_local.prototxt", "Devices' config files to be loaded by inventory manager")
)

type ServiceStatus struct {
	bootzStatus BootzServerStatus
	dhcpStatus  dhcp.DHCPServerStatus
	// TODO: Add image server status.
}

type server struct {
	serv          *grpc.Server
	serviceRef    *service.Service
	lis           net.Listener
	serviceStatus ServiceStatus
	lock          sync.Mutex
	config        ServerConfig
}

type BootzServerStatus string

const (
	BootzServerStatus_UNINITIALIZED BootzServerStatus = "Uninitialized"
	BootzServerStatus_RUNNING       BootzServerStatus = "Running"
	BootzServerStatus_FAILURE       BootzServerStatus = "Failure"
	BootzServerStatus_EXITED        BootzServerStatus = "Exited"
)

type ServerConfig struct {
	// port              string
	DhcpIntf          string
	ArtifactDirectory string
	InventoryConfig   string
}

// Convert address to localhost when no ip is specified.
func convertAddress(addr string) string {
	items := strings.Split(addr, ":")
	listenAddr := addr
	if len(items) == 1 {
		listenAddr = fmt.Sprintf("localhost:%v", addr)
	}
	return listenAddr
}

// readKeyPair reads the cert/key pair from the specified artifacts directory.
// Certs must have the format {name}_pub.pem and keys must have the format {name}_priv.pem.
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

func New() *server {
	return &server{
		serviceStatus: ServiceStatus{
			bootzStatus: BootzServerStatus_UNINITIALIZED,
			dhcpStatus:  dhcp.DHCPServerStatus_UNINITIALIZED,
		},
	}
}

// Starts a bootz server at provided address with provided options.
func (s *server) Start(bootzAddress string, config ServerConfig) (BootzServerStatus, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if config.ArtifactDirectory == "" {
		s.serviceStatus.bootzStatus = BootzServerStatus_FAILURE
		return s.serviceStatus.bootzStatus, fmt.Errorf("no artifact directory selected. specify with the --artifact_dir flag")
	}

	if bootzAddress == "" {
		s.serviceStatus.bootzStatus = BootzServerStatus_FAILURE
		return s.serviceStatus.bootzStatus, fmt.Errorf("Address cannot be empty")
	}

	log.Infof("Setting up server security artifacts: OC, OVs, PDC, VendorCA")
	sa, err := parseSecurityArtifacts()
	if err != nil {
		s.serviceStatus.bootzStatus = BootzServerStatus_FAILURE
		return s.serviceStatus.bootzStatus, err
	}

	log.Infof("Setting up entities")
	em, err := entitymanager.New(config.InventoryConfig)
	if err != nil {
		s.serviceStatus.bootzStatus = BootzServerStatus_FAILURE
		return s.serviceStatus.bootzStatus, fmt.Errorf("unable to initiate inventory manager %v", err)
	}

	s.serviceRef = service.New(em)

	if config.DhcpIntf != "" {
		s.serviceStatus.dhcpStatus, err = startDhcpServer(em, config.DhcpIntf, bootzAddress)
		if err != nil {
			s.serviceStatus.bootzStatus = BootzServerStatus_FAILURE
			return s.serviceStatus.bootzStatus, fmt.Errorf("unable to start dhcp server %v", err)
		}
	}

	trustBundle := x509.NewCertPool()
	if !trustBundle.AppendCertsFromPEM([]byte(sa.PDC.Cert)) {
		s.serviceStatus.bootzStatus = BootzServerStatus_FAILURE
		return s.serviceStatus.bootzStatus, fmt.Errorf("unable to add PDC cert to trust pool")
	}
	tls := &tls.Config{
		Certificates: []tls.Certificate{*sa.TLSKeypair},
		RootCAs:      trustBundle,
	}
	log.Infof("Creating server...")
	newServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(tls)))
	bpb.RegisterBootstrapServer(newServer, s.serviceRef)

	lis, err := net.Listen("tcp", convertAddress(bootzAddress))
	if err != nil {
		s.serviceStatus.bootzStatus = BootzServerStatus_FAILURE
		return s.serviceStatus.bootzStatus, fmt.Errorf("error listening on port: %v", err)
	}
	log.Infof("Server ready and listening on %s", lis.Addr())
	log.Infof("=============================================================================")

	// TODO:  Launch image server
	s.serviceStatus.bootzStatus = BootzServerStatus_RUNNING
	s.serv = newServer
	s.lis = lis

	return s.serviceStatus.bootzStatus, nil

}

// Method for stopping server.
func (s *server) Stop() (BootzServerStatus, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.serv.GracefulStop()
	// TODO: Exit dhcp and image servers.
	s.serviceStatus.bootzStatus = BootzServerStatus_EXITED
	return s.serviceStatus.bootzStatus, nil
}

// Stop and start server again at same address.
func (s *server) Reload() (BootzServerStatus, error) {
	addr := s.lis.Addr().String()
	s.Stop()
	_, err := s.Start(addr, s.config)
	// TODO: Maybe handle address clash.
	// TODO: Stop DHCP and image servers?
	return s.serviceStatus.bootzStatus, err
}

// Returns status of the services.
func (s *server) ServiceStatus() ServiceStatus {
	s.serviceStatus.dhcpStatus = dhcp.Status()
	// TODO: Add image server
	return s.serviceStatus
}

// Entity boot status.
func (s *server) GetBootStatus(router_serial string) (service.BootLog, error) {

	status := s.ServiceStatus()

	if status.dhcpStatus != dhcp.DHCPServerStatus_RUNNING {
		if status.dhcpStatus != dhcp.DHCPServerStatus_UNINITIALIZED {
			return service.BootLog{}, fmt.Errorf("DHCP server not running")
		}
	}

	// TODO: Check if bootz server running.
	// TODO: Check if image server running.

	return s.serviceRef.GetBootStatus(router_serial)
}

func (s *server) IsChassisConnected(chassis service.EntityLookup) bool {
	return s.serviceRef.IsChassisConnected(chassis)
}

func (s *server) ResetStatus(chassis service.EntityLookup) {
	s.serviceRef.ResetStatus(chassis)
}

func startDhcpServer(em *entitymanager.InMemoryEntityManager, intf string, bootzURL string) (dhcp.DHCPServerStatus, error) {
	conf := &dhcp.Config{
		Interface:  intf,
		AddressMap: make(map[string]*dhcp.Entry),
        BootzURL: "bootz://" + bootzURL + "/grpc",
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
