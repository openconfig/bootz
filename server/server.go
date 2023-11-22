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
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"

	log "github.com/golang/glog"
	"github.com/openconfig/bootz/dhcp"
	"github.com/openconfig/bootz/server/entitymanager"
	"github.com/openconfig/bootz/server/service"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	bpb "github.com/openconfig/bootz/proto/bootz"
)

type Server struct {
	serv    *grpc.Server
	lis     net.Listener
	service *service.Service
	httpSrv *http.Server
}

func (s *Server) Start() error {
	return s.serv.Serve(s.lis)
}

func (s *Server) Stop() {
	s.serv.GracefulStop()
	if s.httpSrv != nil {
		s.httpSrv.Shutdown(context.Background())
	}
}

// bootzServerOpts is used to pass optional args to NewServer.
type bootzServerOpts interface {
	isbootzServerOpts()
}

// DHCPOpts is an struct that captures dhcp server config.
type DHCPOpts struct {
	intf string
}

func (*DHCPOpts) isbootzServerOpts() {}

// ImgSrvOpts is an struct that captures dhcp server config.
type ImgSrvOpts struct {
	ImagesLocation string
	Address        string
	CertFile       string
	KeyFile        string
}

func (*ImgSrvOpts) isbootzServerOpts() {}

// InterceptorOpts is an struct that is used to pass an interceptor function.
// This option is added to enable proper testing of bootz.
type InterceptorOpts struct {
	BootzInterceptor grpc.UnaryServerInterceptor
}

func (*InterceptorOpts) isbootzServerOpts() {}

// NewServer start a new Bootz gRPC , dhcp, and image server based on specified flags.
func NewServer(bootzAddr string, em *entitymanager.InMemoryEntityManager, sa *service.SecurityArtifacts, opts ...bootzServerOpts) (*Server, error) {
	var interceptor grpc.ServerOption
	server := &Server{}
	for _, opt := range opts {
		switch opt := opt.(type) {
		case *DHCPOpts:
			if err := StartDhcpServer(em, opt.intf); err != nil {
				return nil, fmt.Errorf("unable to start dhcp server %v", err)
			}
		case *ImgSrvOpts:
			server.httpSrv = StartImageServer(opt)
		case *InterceptorOpts:
			interceptor = grpc.UnaryInterceptor(opt.BootzInterceptor)
		default:
			continue
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
	s := &grpc.Server{}
	if interceptor != nil {
		s = grpc.NewServer(grpc.Creds(credentials.NewTLS(tls)), interceptor)
	} else {
		s = grpc.NewServer(grpc.Creds(credentials.NewTLS(tls)))
	}

	bpb.RegisterBootstrapServer(s, c)

	lis, err := net.Listen("tcp", bootzAddr)
	if err != nil {
		return nil, fmt.Errorf("error listening on port: %v", err)
	}
	log.Infof("Server ready and listening on %s", lis.Addr())
	log.Infof("=============================================================================")
	server.serv = s
	server.service = c
	server.lis = lis
	return server, nil

}

// StartDhcpServer start dhcp server based on the dhcpIntf interface and dhcp configuration added for devices
func StartDhcpServer(em *entitymanager.InMemoryEntityManager, dhcpIntf string) error {
	conf := &dhcp.Config{
		Interface:  dhcpIntf,
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

// StartImageServer starts an https server as an image server.
func StartImageServer(opt *ImgSrvOpts) *http.Server {
	fs := http.FileServer(http.Dir(opt.ImagesLocation))
	mux := http.NewServeMux()
	mux.Handle("/", fs)
	srv := &http.Server{Addr: opt.Address, Handler: fs}
	go func() {
		if err := srv.ListenAndServeTLS(opt.CertFile, opt.KeyFile); err != http.ErrServerClosed {
			log.Fatalf("Error starting image server: %v", err)
		}
	}()
	return srv
}
