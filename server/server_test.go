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
	"crypto/x509"
	"encoding/base64"
	"flag"
	"testing"

	ownercertificate "github.com/openconfig/bootz/common/owner_certificate"

	cpb "github.com/openconfig/bootz/server/proto/config"
)

// TestStartup tests that a gRPC server can be created with the default flags.
func TestStartup(t *testing.T) {
	flag.Parse()
	cert, key, err := ownercertificate.NewRSACertificate("Server Test", "", nil, nil)
	keyRaw, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}
	certStr := base64.StdEncoding.EncodeToString(cert.Raw)
	keyStr := base64.StdEncoding.EncodeToString(keyRaw)
	config := &cpb.Config{
		ServerAddress: "127.0.0.1",
		ServerPort:    "15006",
		TrustAnchor: &cpb.CertKeyPair{
			Cert: certStr,
			Key:  keyStr,
		},
		OwnerCertificate: &cpb.CertKeyPair{
			Cert: certStr,
			Key:  keyStr,
		},
	}
	if _, err := NewServer(config); err != nil {
		t.Fatalf("newServer() err = %v, want nil", err)
	}
}
