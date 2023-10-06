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

package main

import (
	"fmt"
	"testing"
)


// TestStartup tests that a gRPC server can be created with the default flags.
func TestStartup(t *testing.T) {

    serv := &server{}
    
    address := "127.0.0.1:5000"

    config := ServerConfig{
        DhcpIntf          : "",
        ArtifactDirectory : "../testdata/",
        InventoryConfig   : "../testdata/inventory_local.prototxt",
    }

    status, err := serv.Start(address, config)

	if err != nil {
		t.Fatalf("server.Start err = %v, want nil", err)
	}

    if status != "Running" {
        t.Fatalf("Expected: Running, Received: %s", status)
    }

    fmt.Printf("status: %s\n", serv.status)

    fmt.Printf("addr: %s\n", serv.lis.Addr())
    
    serv.serv.GracefulStop()

}

func TestStartupFailure(t *testing.T) {

    serv := &server{}
    
    address := "127.0.0.1:5000"

    config := ServerConfig{
        DhcpIntf          : "",
        ArtifactDirectory : "../testdata/",
        InventoryConfig   : "../testdata/inventory_local.prototxt",
    }

    status, err := serv.Start(address, config)

	if err != nil {
		t.Fatalf("server.Start err = %v, want nil", err)
	}

    if status != "Running" {
        t.Fatalf("Expected: Running, Received: %s", status)
    }

    fmt.Printf("status: %s\n", serv.status)

    fmt.Printf("addr: %s\n", serv.lis.Addr())
    
    serv.serv.GracefulStop()

}


func TestStop(t *testing.T) {
    
    serv := &server{}
    
    address := "127.0.0.1:5001"

    config := ServerConfig{
        DhcpIntf          : "",
        ArtifactDirectory : "../testdata/",
        InventoryConfig   : "../testdata/inventory_local.prototxt",
    }

    status, err := serv.Start(address, config)

	if err != nil {
		t.Fatalf("server.Start err = %v, want nil", err)
	}

    if status != "Running" {
        t.Fatalf("Expected: Running, Received: %s", status)
    }

    serv.Stop()
    
    if status != "Exited" {
        t.Fatalf("Expected: Running, Received: %s", status)
    }
    
}

func TestRestart(t *testing.T) {
    
    serv := &server{}
    
    address := "127.0.0.1:5002"

    config := ServerConfig{
        DhcpIntf          : "",
        ArtifactDirectory : "../testdata/",
        InventoryConfig   : "../testdata/inventory_local.prototxt",
    }

    status, err := serv.Start(address, config)

	if err != nil {
		t.Fatalf("server.Start err = %v, want nil", err)
	}

    if status != "Running" {
        t.Fatalf("Expected: Running, Received: %s", status)
    }

    serv.Reload()

    if status != "Running" {
        t.Fatalf("Expected: Running, Received: %s", status)
    }
    
}
