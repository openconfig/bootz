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

package controller

import (
	"context"
	"net"
	"sync"

	log "github.com/golang/glog"
	"github.com/openconfig/bootz/server/sutstate"
	pb "github.com/openconfig/bootz/server/tests/proto/sut"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

type Server struct {
	pb.UnimplementedBootzControllerServer
	grpcServer *grpc.Server
	publicURL  string

	mu          sync.Mutex
	subscribers []chan *pb.SubscribeResponse
}

func New(publicURL string) *Server {
	return &Server{
		publicURL: publicURL,
	}
}

// Start starts the BootzController SUT gRPC server.
func (s *Server) Start(addr string) error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.grpcServer = grpc.NewServer()
	pb.RegisterBootzControllerServer(s.grpcServer, s)
	reflection.Register(s.grpcServer)
	log.Infof("Starting BootzController SUT gRPC server on %s", addr)
	go func() {
		if err := s.grpcServer.Serve(lis); err != nil {
			log.Errorf("BootzController SUT gRPC server failed: %v", err)
		}
	}()
	return nil
}

// Stop stops the BootzController SUT gRPC server.
func (s *Server) Stop() {
	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ch := range s.subscribers {
		close(ch)
	}
	s.subscribers = nil
}

func (s *Server) SetBootstrapData(ctx context.Context, req *pb.SetBootstrapDataRequest) (*pb.SetBootstrapDataResponse, error) {
	sutstate.SetBootstrapData(req.GetBootstrapData())
	log.Infof("BootzController: Set bootstrap data")
	return &pb.SetBootstrapDataResponse{}, nil
}

func (s *Server) SetSecurityArtifacts(ctx context.Context, req *pb.SetSecurityArtifactsRequest) (*pb.SetSecurityArtifactsResponse, error) {
	sutstate.SetSecurityArtifacts(req.GetSecurityArtifacts())
	log.Infof("BootzController: Set security artifacts")
	return &pb.SetSecurityArtifactsResponse{}, nil
}

func (s *Server) SetRecoveryData(ctx context.Context, req *pb.SetRecoveryDataRequest) (*pb.SetRecoveryDataResponse, error) {
	sutstate.SetRecoveryData(req.GetRecoveryData())
	log.Infof("BootzController: Set recovery data")
	return &pb.SetRecoveryDataResponse{}, nil
}

func (s *Server) GetBootzURL(ctx context.Context, req *pb.GetBootzURLRequest) (*pb.GetBootzURLResponse, error) {
	return &pb.GetBootzURLResponse{
		BootzUrl: s.publicURL,
	}, nil
}

// NotifyEvent is called by the device-facing service to notify subscribers of events.
func (s *Server) NotifyEvent(resp *pb.SubscribeResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ch := range s.subscribers {
		select {
		case ch <- resp:
		default:
			log.Warningf("Subscriber channel full, dropping event: %v", resp)
		}
	}
}

func (s *Server) Subscribe(req *pb.SubscribeRequest, stream pb.BootzController_SubscribeServer) error {
	ch := make(chan *pb.SubscribeResponse, 100)

	s.mu.Lock()
	s.subscribers = append(s.subscribers, ch)
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		for i, c := range s.subscribers {
			if c == ch {
				s.subscribers = append(s.subscribers[:i], s.subscribers[i+1:]...)
				break
			}
		}
		s.mu.Unlock()
		close(ch)
	}()

	log.Infof("BootzController: New subscriber registered")

	for {
		select {
		case <-stream.Context().Done():
			log.Infof("BootzController: Subscriber context done")
			return stream.Context().Err()
		case resp, ok := <-ch:
			if !ok {
				return nil
			}
			if err := stream.Send(resp); err != nil {
				log.Errorf("Failed to send event to subscriber: %v", err)
				return err
			}
		}
	}
}