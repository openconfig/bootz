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

package sutserver

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	log "github.com/golang/glog"
	"github.com/openconfig/bootz/dhcp/plugins/slease"
	pb "github.com/openconfig/bootz/server/tests/proto/sut"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

type Server struct {
	pb.UnimplementedDHCPServiceServer
	grpcServer *grpc.Server
}

func New() *Server {
	return &Server{}
}

// Start starts the DHCP SUT gRPC server.
func (s *Server) Start(addr string) error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.grpcServer = grpc.NewServer()
	pb.RegisterDHCPServiceServer(s.grpcServer, s)
	reflection.Register(s.grpcServer)
	log.Infof("Starting DHCP SUT gRPC server on %s", addr)
	go func() {
		if err := s.grpcServer.Serve(lis); err != nil {
			log.Errorf("DHCP SUT gRPC server failed: %v", err)
		}
	}()
	return nil
}

// Stop stops the DHCP SUT gRPC server.
func (s *Server) Stop() {
	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
	}
}

// CreateLease creates a DHCP lease dynamically.
func (s *Server) CreateLease(ctx context.Context, req *pb.CreateLeaseRequest) (*pb.CreateLeaseResponse, error) {
	ip, err := netip.ParseAddr(req.GetIpAddress())
	if err != nil {
		return nil, err
	}
	gw := net.ParseIP(req.GetGateway())
	if gw == nil {
		return nil, fmt.Errorf("invalid gateway: %s", req.GetGateway())
	}

	mask := net.CIDRMask(int(req.GetMaskLen()), ip.BitLen())

	for _, mac := range req.GetMacAddresses() {
		slease.AddRecord4(mac, net.ParseIP(req.GetIpAddress()), mask, gw)
	}

	return &pb.CreateLeaseResponse{}, nil
}

// RemoveLease removes a DHCP lease dynamically.
func (s *Server) RemoveLease(ctx context.Context, req *pb.RemoveLeaseRequest) (*pb.RemoveLeaseResponse, error) {
	for _, mac := range req.GetMacAddresses() {
		slease.RemoveRecord4(mac)
	}
	return &pb.RemoveLeaseResponse{}, nil
}