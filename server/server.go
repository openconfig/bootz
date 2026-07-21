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
	"google.golang.org/grpc/reflection"

	bpb "github.com/openconfig/bootz/proto/bootz"
	tpb "github.com/openconfig/bootz/proto/test"
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

// Opts is used to pass optional args to NewServer.
type Opts interface {
	IsBootzServerOpts()
}

// NewServer start a new Bootz gRPC, DHCP, and HTTP image server based on specified flags.
func NewServer(config *cpb.Config, opts ...Opts) (*Server, error) {
	if config.GetServerPort() == "" {
		return nil, fmt.Errorf("bootz server port must be specified")
	}
	ip := net.ParseIP(config.GetServerAddress())
	if ip == nil {
		return nil, fmt.Errorf("invalid Bootz server IP address: %q", config.GetServerAddress())
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

	for _, opt := range opts {
		switch opt := opt.(type) {
		case *dhcp.Opts:
			if err := dhcp.Start(opt.Config); err != nil {
				return nil, fmt.Errorf("unable to start dhcp server %v", err)
			}
		case *http.Opts:
			if err := http.Start(opt); err != nil {
				return nil, fmt.Errorf("unable to start http server %v", err)
			}
		default:
			continue
		}
	}

	log.Infof("Creating Bootz server...")
	c, err := service.New(am, cm, &biz.DefaultTPM20Utils{})
	if err != nil {
		return nil, fmt.Errorf("error creating service: %v", err)
	}
	s := grpc.NewServer(grpc.Creds(credentials.NewTLS(conf)))
	bpb.RegisterBootstrapServer(s, c)
	// Register the test service only if we are in test mode.
	if config.GetTestMode() {
		tpb.RegisterTestServer(s, cm)
	}
	// Register reflection service on gRPC server.
	reflection.Register(s)

	lis, err := net.Listen("tcp", ":"+config.GetServerPort())
	if err != nil {
		return nil, fmt.Errorf("error listening on port: %v", err)
	}
	log.Infof("Bootz server ready and listening on %s", lis.Addr())
	log.Infof("=============================================================================")

	return &Server{
		serv:    s,
		lis:     lis,
		service: c,
	}, nil
}
