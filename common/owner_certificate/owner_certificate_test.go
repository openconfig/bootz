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

	"go.mozilla.org/pkcs7"
)

// Tests that the CMS structure can be created and that it can be verified with a PDC.
func TestGenerateAndVerify(t *testing.T) {
	pdc, pdcPrivateKey, err := NewRSACertificate("Pinned Domain Cert", "", nil, nil)
	if err != nil {
		t.Fatalf("failed to create PDC: %v", err)
	}
	oc, ocPrivateKey, err := NewRSACertificate("Owner Certificate", "", pdc, pdcPrivateKey)
	if err != nil {
		t.Fatalf("failed to create owner certificate: %v", err)
	}
	cms, err := GenerateCMS(oc, ocPrivateKey)
	if err != nil {
		t.Fatalf("failed to create CMS: %v", err)
	}
	pdcPool := x509.NewCertPool()
	pdcPool.AddCert(pdc)
	gotCert, err := Verify(cms, pdcPool)
	if err != nil {
		t.Fatalf("failed to verify owner certificate: %v", err)
	}
	if !gotCert.Equal(oc) {
		t.Errorf("Verify() returned certificate CN=%q, want CN=%q", gotCert.Subject.CommonName, oc.Subject.CommonName)
	}
}

func TestVerifyReturnsSignerWhenExtraCertPrepended(t *testing.T) {
	pdc, pdcPrivateKey, err := NewRSACertificate("Pinned Domain Cert", "", nil, nil)
	if err != nil {
		t.Fatalf("failed to create PDC: %v", err)
	}
	oc, ocPrivateKey, err := NewRSACertificate("Legit Owner Certificate", "", pdc, pdcPrivateKey)
	if err != nil {
		t.Fatalf("failed to create owner certificate: %v", err)
	}
	evilCert, _, err := NewRSACertificate("Attacker Certificate", "", nil, nil)
	if err != nil {
		t.Fatalf("failed to create attacker certificate: %v", err)
	}

	signedMessage, err := pkcs7.NewSignedData(nil)
	if err != nil {
		t.Fatalf("failed to initialize signed data: %v", err)
	}
	signedMessage.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	signedMessage.AddCertificate(evilCert)
	if err := signedMessage.AddSigner(oc, ocPrivateKey, pkcs7.SignerInfoConfig{}); err != nil {
		t.Fatalf("failed to add signer: %v", err)
	}
	cms, err := signedMessage.Finish()
	if err != nil {
		t.Fatalf("failed to finish CMS: %v", err)
	}

	pdcPool := x509.NewCertPool()
	pdcPool.AddCert(pdc)
	gotCert, err := Verify(cms, pdcPool)
	if err != nil {
		t.Fatalf("failed to verify owner certificate: %v", err)
	}
	if !gotCert.Equal(oc) {
		t.Errorf("Verify() returned certificate CN=%q, want CN=%q", gotCert.Subject.CommonName, oc.Subject.CommonName)
	}
}

func TestVerifyRejectsMultipleSigners(t *testing.T) {
	pdc, pdcPrivateKey, err := NewRSACertificate("Pinned Domain Cert", "", nil, nil)
	if err != nil {
		t.Fatalf("failed to create PDC: %v", err)
	}
	oc1, oc1PrivateKey, err := NewRSACertificate("Owner Certificate 1", "", pdc, pdcPrivateKey)
	if err != nil {
		t.Fatalf("failed to create owner certificate 1: %v", err)
	}
	oc2, oc2PrivateKey, err := NewRSACertificate("Owner Certificate 2", "", pdc, pdcPrivateKey)
	if err != nil {
		t.Fatalf("failed to create owner certificate 2: %v", err)
	}

	signedMessage, err := pkcs7.NewSignedData(nil)
	if err != nil {
		t.Fatalf("failed to initialize signed data: %v", err)
	}
	signedMessage.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	if err := signedMessage.AddSigner(oc1, oc1PrivateKey, pkcs7.SignerInfoConfig{}); err != nil {
		t.Fatalf("failed to add signer 1: %v", err)
	}
	if err := signedMessage.AddSigner(oc2, oc2PrivateKey, pkcs7.SignerInfoConfig{}); err != nil {
		t.Fatalf("failed to add signer 2: %v", err)
	}
	cms, err := signedMessage.Finish()
	if err != nil {
		t.Fatalf("failed to finish CMS: %v", err)
	}

	pdcPool := x509.NewCertPool()
	pdcPool.AddCert(pdc)
	if _, err := Verify(cms, pdcPool); err == nil {
		t.Errorf("Verify() with multiple signers succeeded, want error")
	}
}
