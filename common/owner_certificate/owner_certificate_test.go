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

package ownercertificate

import (
	"crypto/x509"
	"testing"

	_ "embed"

	artifacts "github.com/openconfig/bootz/testdata"
)

// Tests that the CMS structure can be created and that it can be verified with a PDC.
func TestGenerateAndVerify(t *testing.T) {
	pdc, pdcPrivateKey, err := artifacts.NewCertificateAuthority("Pinned Domain Cert", "Google", "localhost")
	if err != nil {
		t.Fatalf("NewCertificateAuthority(): %v", err)
	}
	oc, ocPrivateKey, err := artifacts.NewSignedCertificate("Owner Certificate", "Google", "localhost", pdc, pdcPrivateKey)
	if err != nil {
		t.Fatalf("NewSignedCertificate(): %v", err)
	}
	cms, err := GenerateCMS(oc, ocPrivateKey)
	if err != nil {
		t.Fatalf("GenerateCMS(): %v", err)
	}
	pdcPool := x509.NewCertPool()
	pdcPool.AddCert(pdc)
	_, err = Verify(cms, pdcPool)
	if err != nil {
		t.Fatalf("Verify(): %v", err)
	}
}
