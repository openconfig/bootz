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

// Package server is the Bootz server reference implementation.
//
// The bootz server will provide a simple file based bootstrap
// implementation for devices. The service can be extended by
// providing your own implementation of the entity manager.
package server

import (
	"crypto/x509/pkix"
	"fmt"
	"net"
	"strings"

	log "github.com/golang/glog"
	"github.com/openconfig/attestz/service/biz"
	bootztls "github.com/openconfig/bootz/common/tls"
	"github.com/openconfig/bootz/dhcp"
	"github.com/openconfig/bootz/http"
	"github.com/openconfig/bootz/server/artifactmanager"
	"github.com/openconfig/bootz/server/chassismanager"
	"github.com/openconfig/bootz/server/service"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	dpb "github.com/openconfig/bootz/dhcp/proto/config"
	bpb "github.com/openconfig/bootz/proto/bootz"
	cpb "github.com/openconfig/bootz/server/proto/config"
)

// Server is the bootz emulator server.
type Server struct {
	serv    *grpc.Server
	lis     net.Listener
	service *service.Service
}

// Start starts up the bootz emulator server.
func (s *Server) Start() error {
	return s.serv.Serve(s.lis)
}

// Stop shuts down the bootz emulator server.
func (s *Server) Stop() {
	s.serv.GracefulStop()
}

// bootzServerOpts is used to pass optional args to NewServer.
type bootzServerOpts interface {
	isbootzServerOpts()
}

// DHCPOpts is an struct that captures dhcp server config.
type DHCPOpts struct {
	Config *dpb.Config
}

func (*DHCPOpts) isbootzServerOpts() {}

// ImgSrvOpts is an struct that captures dhcp server config.
type ImgSrvOpts struct {
	Address        string
	ImagesLocation string
}

func (*ImgSrvOpts) isbootzServerOpts() {}

// InterceptorOpts is an struct that is used to pass an interceptor function.
// This option is added to enable proper testing of bootz.
type InterceptorOpts struct {
	BootzInterceptor grpc.UnaryServerInterceptor
}

func (*InterceptorOpts) isbootzServerOpts() {}

// NewServer start a new Bootz gRPC, DHCP, and HTTP image server based on specified flags.
func NewServer(config *cpb.Config, opts ...bootzServerOpts) (*Server, error) {
	addrParts := strings.Split(config.GetServerAddress(), ":")
	if len(addrParts) != 2 {
		return nil, fmt.Errorf("bootz server address must be in the format of 'IP:Port', got: %q", config.GetServerAddress())
	}
	ip := net.ParseIP(addrParts[0])
	if ip == nil {
		return nil, fmt.Errorf("invalid Bootz server IP address: %q", addrParts[0])
	}
	am, err := artifactmanager.New(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create ArtifactManager: %v", err)
	}
	cm := chassismanager.New(config)
	trustAnchorCert, trustAnchorKey := am.BootzServerTrustAnchorKeyPair()
	conf, err := bootztls.TLSConfiguration(&bootztls.Opts{
		CAPrivateKey: trustAnchorKey,
		CACert:       trustAnchorCert,
		IPAddress:    ip,
		ClientCAs:    am.VendorCABundle(),
		ServerCertSubject: &pkix.Name{
			CommonName: "Bootz Server TLS Certificate",
		},
	})
	if err != nil {
		return nil, fmt.Errorf("error creating bootz server cert: %v", err)
	}

	var interceptor grpc.ServerOption
	for _, opt := range opts {
		switch opt := opt.(type) {
		case *DHCPOpts:
			if err := dhcp.Start(opt.Config); err != nil {
				return nil, fmt.Errorf("unable to start dhcp server %v", err)
			}
		case *ImgSrvOpts:
			if err := StartImageServer(opt); err != nil {
				return nil, fmt.Errorf("unable to start image server %v", err)
			}
		case *InterceptorOpts:
			interceptor = grpc.UnaryInterceptor(opt.BootzInterceptor)
		default:
			continue
		}
	}

	log.Infof("Creating server...")
	c, err := service.New(am, cm, &biz.DefaultTPM20Utils{})
	if err != nil {
		return nil, fmt.Errorf("error creating service: %v", err)
	}
	s := &grpc.Server{}
	if interceptor != nil {
		s = grpc.NewServer(grpc.Creds(credentials.NewTLS(conf)), interceptor)
	} else {
		s = grpc.NewServer(grpc.Creds(credentials.NewTLS(conf)))
	}
	bpb.RegisterBootstrapServer(s, c)

	lis, err := net.Listen("tcp", ":"+addrParts[1])
	if err != nil {
		return nil, fmt.Errorf("error listening on port: %v", err)
	}
	log.Infof("Server ready and listening on %s", lis.Addr())
	log.Infof("=============================================================================")

	return &Server{
		serv:    s,
		lis:     lis,
		service: c,
	}, nil
}

// StartImageServer starts an http server as an image server.
func StartImageServer(opt *ImgSrvOpts) error {
	conf := &http.Config{
		Address: opt.Address,
		Folder:  opt.ImagesLocation,
	}
	return http.Start(conf)
}
