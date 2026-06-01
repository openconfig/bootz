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
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"

	log "github.com/golang/glog"
	bootzpb "github.com/openconfig/bootz/proto/bootz"
	"github.com/openconfig/bootz/server/sutstate"
	pb "github.com/openconfig/bootz/server/tests/proto/sut"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

type Server struct {
	pb.UnimplementedImageServiceServer
	grpcServer *grpc.Server
	folder     string
	publicURL  string
}

func New(folder string, publicURL string) *Server {
	return &Server{
		folder:    folder,
		publicURL: publicURL,
	}
}

// Start starts the HTTP SUT gRPC server.
func (s *Server) Start(addr string) error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.grpcServer = grpc.NewServer()
	pb.RegisterImageServiceServer(s.grpcServer, s)
	reflection.Register(s.grpcServer)
	log.Infof("Starting HTTP SUT gRPC server on %s", addr)
	go func() {
		if err := s.grpcServer.Serve(lis); err != nil {
			log.Errorf("HTTP SUT gRPC server failed: %v", err)
		}
	}()
	return nil
}

// Stop stops the HTTP SUT gRPC server.
func (s *Server) Stop() {
	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
	}
}

// Upload handles image upload/download instructions.
func (s *Server) Upload(ctx context.Context, req *pb.UploadRequest) (*pb.UploadResponse, error){
	img := req.GetImage()
	if img == nil {
		return nil, fmt.Errorf("image is required")
	}

	downloadURL := img.GetDownloadUri()
	finalURL := downloadURL

	if img.GetReuploadToSut() {
		filename := fmt.Sprintf("%s-%s", img.GetName(), img.GetVersion())
		localPath := filepath.Join(s.folder, filename)

		log.Infof("Downloading image from %s to %s", downloadURL, localPath)
		if err := downloadFile(ctx, downloadURL, localPath); err != nil {
			return nil, fmt.Errorf("failed to download image: %w", err)
		}

		finalURL = fmt.Sprintf("%s/%s", s.publicURL, filename)
		log.Infof("Image re-uploaded, available at: %s", finalURL)
	}

	resp := &pb.UploadResponse{
		Image: &bootzpb.SoftwareImage{
			Name:          img.GetName(),
			Version:       img.GetVersion(),
			Url:           finalURL,
			OsImageHash:   img.GetOsImageHash(),
			HashAlgorithm: img.GetHashAlgorithm(),
		},
	}
	sutstate.SetSoftwareImage(resp.Image)
	return resp, nil
}

func downloadFile(ctx context.Context, url string, filepath string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}
