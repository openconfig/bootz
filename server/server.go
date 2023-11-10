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
	"sync"
	"time"

	log "github.com/golang/glog"
	"github.com/openconfig/bootz/dhcp"
	"github.com/openconfig/bootz/server/entitymanager"
	"github.com/openconfig/bootz/server/service"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	bpb "github.com/openconfig/bootz/proto/bootz"
)

type server struct {
	serv    *grpc.Server
	lis     net.Listener
	service *service.Service
}

func (s *server) Start() error {
	return s.serv.Serve(s.lis)
}

func (s *server) Stop() {
	s.serv.GracefulStop()
}

type bootzServerOpts interface {
	isbootzServerOpts()
}

type DHCPOpts struct {
	intf string
}

func (*DHCPOpts) isbootzServerOpts() {}

type ImgSrvOpts struct {
	ImagesLocation string
	Address        string
	CertFile       string
	KeyFile        string
}

func (*ImgSrvOpts) isbootzServerOpts() {}

// NewServer start a new Bootz gRPC , dhcp, and image server based on specefied flags.
func NewServer(bootzAddr string, em *entitymanager.InMemoryEntityManager, sa *service.SecurityArtifacts, opts ...bootzServerOpts) (*server, error) {

	for _, opt := range opts {
		switch opt := opt.(type) {
		case *DHCPOpts:
			if err := StartDhcpServer(em, opt.intf); err != nil {
				return nil, fmt.Errorf("unable to start dhcp server %v", err)
			}
		case *ImgSrvOpts:
			StartImgaeServer(opt)
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
	s := grpc.NewServer(grpc.Creds(credentials.NewTLS(tls)), grpc.UnaryInterceptor(bootzInterceptor))
	bpb.RegisterBootstrapServer(s, c)

	lis, err := net.Listen("tcp", bootzAddr)
	if err != nil {
		return nil, fmt.Errorf("error listening on port: %v", err)
	}
	log.Infof("Server ready and listening on %s", lis.Addr())
	log.Infof("=============================================================================")
	return &server{serv: s, lis: lis, service: c}, nil

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

func StartImgaeServer(opt *ImgSrvOpts) {
	go func() {
		fs := http.FileServer(http.Dir(opt.ImagesLocation))
		http.Handle("/", fs)
		if err := http.ListenAndServeTLS(opt.Address, opt.CertFile, opt.KeyFile, fs); err != nil {
			log.Fatalf("Error starting image server: %v", err)
		}
	}()
}

// A struct to record the boot logs for connected chassis.
type BootzReqLog struct {
	StartTimeStamp int
	EndTimeStamp   int
	BootResponse   *bpb.BootstrapDataResponse
	BootRequest    *bpb.GetBootstrapDataRequest
	Err            error
}

type BootzStatusLog struct {
	CardStatus []bpb.ControlCardState_ControlCardStatus
	Status     []bpb.ReportStatusRequest_BootstrapStatus
}
type BootzLogs map[service.EntityLookup]*BootzReqLog
type BootzStatus map[string]*BootzStatusLog

var (
	bootzReqLogs    = BootzLogs{}
	bootzStatusLogs = BootzStatus{}
	muRw            sync.RWMutex
)

func bootzInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	start := time.Now()
	switch breq := req.(type) {
	case *bpb.GetBootstrapDataRequest:
		bootzLog := &BootzReqLog{
			StartTimeStamp: start.Nanosecond(),
			BootRequest:    breq,
		}
		h, err := handler(ctx, req)
		bootzLog.Err = err
		bres, _ := h.(*bpb.BootstrapDataResponse)
		bootzLog.BootResponse = bres
		bootzLog.EndTimeStamp = time.Now().Nanosecond()
		ch := breq.GetChassisDescriptor()
		muRw.Lock()
		defer muRw.Unlock()
		if ch.GetSerialNumber() != "" {
			bootzReqLogs[service.EntityLookup{SerialNumber: ch.GetSerialNumber(), Manufacturer: ch.GetManufacturer()}] = bootzLog
		}
		ccStatus := breq.GetControlCardState()
		if ccStatus != nil && ccStatus.GetSerialNumber() != "" {
			bootzReqLogs[service.EntityLookup{SerialNumber: ccStatus.GetSerialNumber(), Manufacturer: ch.GetManufacturer()}] = bootzLog
		}
		return h, err
	case *bpb.ReportStatusRequest:
		muRw.Lock()
		defer muRw.Unlock()
		for _, cc := range breq.GetStates() {
			serial := cc.GetSerialNumber()
			_, ok := bootzStatusLogs[cc.GetSerialNumber()]
			if !ok {
				bootzStatusLogs[serial] = &BootzStatusLog{
					CardStatus: []bpb.ControlCardState_ControlCardStatus{},
					Status:     []bpb.ReportStatusRequest_BootstrapStatus{},
				}
			}
			bootzStatusLogs[serial].Status = append(bootzStatusLogs[serial].Status, breq.GetStatus())
			bootzStatusLogs[serial].CardStatus = append(bootzStatusLogs[serial].CardStatus, cc.GetStatus())
		}
		return handler(ctx, req)
	default:
		return handler(ctx, req)

	}
}
