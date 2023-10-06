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
	"testing"
)


// TestStartup tests that a gRPC server can be created with the default flags.
func TestStartup(t *testing.T) {
    
    tests := []struct {
        name string
        address string
    }{
        { "Start server success", "127.0.0.1:5000", },
    }


    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {

            serv := &server{}
            
            config := ServerConfig{
                DhcpIntf          : "",
                ArtifactDirectory : "../testdata/",
                InventoryConfig   : "../testdata/inventory_local.prototxt",
            }

            status, err := serv.Start(tt.address, config)

            if err != nil {
                t.Errorf("server.Start err = %v, want nil", err)
            }

            if status != "Running" {
                t.Errorf("Expected: Running, Received: %s", status)
            }

            serv.serv.GracefulStop()
            
        })
    }
    

}

func TestStartupFailure(t *testing.T) {
    
    tests := []struct {
        name string
        address string
        wantErr string
    }{
        { "Start server failure", "8.8.8.8:5000",
            "error listening on port: listen tcp 8.8.8.8:5000: bind: can't assign requested address", },
    }


    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {

            serv := &server{}
            
            config := ServerConfig{
                DhcpIntf          : "",
                ArtifactDirectory : "../testdata/",
                InventoryConfig   : "../testdata/inventory_local.prototxt",
            }

            status, err := serv.Start(tt.address, config)

            if err.Error() != tt.wantErr {
                t.Errorf("server.Start err = %v, want nil", err)
                
            }

            if status != "Failure" {
                t.Errorf("Expected: Running, Received: %s", status)
            }
            
        })
    }

}


func TestStop(t *testing.T) {
    
    tests := []struct {
        name string
        address string
    }{
        { "Stop server", "127.0.0.1:5001", },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {

            serv := &server{}
            
            config := ServerConfig{
                DhcpIntf          : "",
                ArtifactDirectory : "../testdata/",
                InventoryConfig   : "../testdata/inventory_local.prototxt",
            }

            status, err := serv.Start(tt.address, config)

            if err != nil {
                t.Errorf("server.Start err = %v, want nil", err)
            }

            if status != "Running" {
                t.Errorf("Expected: Running, Received: %s", status)
            }

            status, err = serv.Stop()
            
            if status != "Exited" {
                t.Errorf("Expected: Exited, Received: %s", status)
            }
        })
    }
    
    
}

func TestReload(t *testing.T) {

    tests := []struct {
        name string
        address string
    }{
        { "Reload server", "127.0.0.1:5002", },
    }

    // TODO: Add test for reload failure from address clash 

    for _, tt := range tests {
        
        t.Run(tt.name, func(t *testing.T) {
            
            serv := &server{}
            
            config := ServerConfig{
                DhcpIntf          : "",
                ArtifactDirectory : "../testdata/",
                InventoryConfig   : "../testdata/inventory_local.prototxt",
            }

            status, err := serv.Start(tt.address, config)

            if err != nil {
                t.Errorf("server.Start err = %v, want nil", err)
            }

            if status != "Running" {
                t.Errorf("Before reload- Expected: Running, Received: %s", status)
            }

            serv.Reload()

            if status != "Running" {
                t.Errorf("After reload- Expected: Running, Received: %s", status)
            }
        })
    }
}
