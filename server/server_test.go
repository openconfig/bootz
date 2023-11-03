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
	"flag"
	"testing"

	"github.com/openconfig/bootz/server/entitymanager"
	artifacts "github.com/openconfig/bootz/testdata"
)

// TestStartup tests that a gRPC server can be created with the default flags.
func TestStartup(t *testing.T) {
	sa, err := artifacts.GenerateSecurityArtifacts([]string{"123A", "123B"}, "Google", "Cisco")
	if err != nil {
		t.Fatalf("unable to generate server artifacts: %v", err)
	}
	flag.Parse()
	_, err = NewServer("localhost:5000", &entitymanager.InMemoryEntityManager{}, sa)
	if err != nil {
		t.Fatalf("newServer() err = %v, want nil", err)
	}
}
