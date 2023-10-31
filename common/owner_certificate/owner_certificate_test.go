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
	"encoding/pem"
	"testing"

	_ "embed"
)

var (
	//go:embed testdata/oc_pub.pem
	ocPub []byte
	//go:embed testdata/pdc_pub.pem
	pdcPub []byte
	//go:embed testdata/oc_priv.pem
	ocPriv []byte
)

// Tests that the CMS structure can be created and that it can be verified with a PDC.
func TestGenerateAndVerify(t *testing.T) {
	block, _ := pem.Decode(ocPub)
	if block == nil {
		t.Fatalf("error decoding OC certificate")
	}
	ownerCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	block, _ = pem.Decode(ocPriv)
	if block == nil {
		t.Fatalf("error decoding OC private key")
	}
	ownerCertPrivateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	block, _ = pem.Decode(pdcPub)
	if block == nil {
		t.Fatalf("error decoding PDC certificate")
	}
	pdcCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	cms, err := GenerateCMS(ownerCert, ownerCertPrivateKey)
	if err != nil {
		t.Fatalf("error generating CMS: %v", err)
	}
	pdcPool := x509.NewCertPool()
	pdcPool.AddCert(pdcCert)
	_, err = Verify(cms, pdcPool)
	if err != nil {
		t.Fatalf("error verifying OC: %v", err)
	}

}
