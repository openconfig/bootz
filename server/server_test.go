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

package server

import (
	"strings"
	"testing"
)

// TestStartup tests that a gRPC server can be created with the default flags.
func TestStartup(t *testing.T) {

	tests := []struct {
		name    string
		address string
	}{
		{"Start server success", "127.0.0.1:5000"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			serv := &server{}

			config := ServerConfig{
				DhcpIntf:          "",
				ArtifactDirectory: "../testdata/",
				InventoryConfig:   "../testdata/inventory_local.prototxt",
			}

			status, err := serv.Start(tt.address, config)

			if err != nil {
				t.Errorf("server.Start err = %v, want nil", err)
			}

			if status != BootzServerStatus_RUNNING {
				t.Errorf("Expected: %s, Received: %s", BootzServerStatus_RUNNING, status)
			}

			serv.serv.GracefulStop()

		})
	}

}

func TestStartupFailure(t *testing.T) {

	tests := []struct {
		name    string
		address string
		wantErr string
	}{
		{
			"Start server failure",
			"8.8.8.8:5000",
			"8.8.8.8:5000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			serv := New()

			config := ServerConfig{
				DhcpIntf:          "",
				ArtifactDirectory: "../testdata/",
				InventoryConfig:   "../testdata/inventory_local.prototxt",
			}

			status, err := serv.Start(tt.address, config)

			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("server.Start err = %v, want nil", err)

			}

			if status != BootzServerStatus_FAILURE {
				t.Errorf("Expected: %s, Received: %s", BootzServerStatus_FAILURE, status)
			}

		})
	}

}

func TestStop(t *testing.T) {

	tests := []struct {
		name    string
		address string
	}{
		{"Stop server", "127.0.0.1:5001"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			serv := &server{}

			config := ServerConfig{
				DhcpIntf:          "",
				ArtifactDirectory: "../testdata/",
				InventoryConfig:   "../testdata/inventory_local.prototxt",
			}

			status, err := serv.Start(tt.address, config)

			if err != nil {
				t.Errorf("server.Start err = %v, want nil", err)
			}

			if status != BootzServerStatus_RUNNING {
				t.Errorf("Expected: %s, Received: %s", BootzServerStatus_RUNNING, status)
			}

			status, err = serv.Stop()

			if status != BootzServerStatus_EXITED {
				t.Errorf("Expected: %s, Received: %s", BootzServerStatus_EXITED, status)
			}
		})
	}

}

func TestReload(t *testing.T) {

	tests := []struct {
		name    string
		address string
	}{
		{"Reload server", "127.0.0.1:5002"},
	}

	// TODO: Add test for reload failure from address clash

	for _, tt := range tests {

		t.Run(tt.name, func(t *testing.T) {

			serv := &server{}

			config := ServerConfig{
				DhcpIntf:          "",
				ArtifactDirectory: "../testdata/",
				InventoryConfig:   "../testdata/inventory_local.prototxt",
			}

			status, err := serv.Start(tt.address, config)

			if err != nil {
				t.Errorf("server.Start err = %v, want nil", err)
			}

			if status != BootzServerStatus_RUNNING {
				t.Errorf("Before reload- Expected: %s, Received: %s", BootzServerStatus_RUNNING, status)
			}

			serv.Reload()

			if status != BootzServerStatus_RUNNING {
				t.Errorf("After reload- Expected: %s, Received: %s", BootzServerStatus_RUNNING, status)
			}
		})
	}
}
