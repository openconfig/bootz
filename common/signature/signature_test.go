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

package signature

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"testing"
)

func keyPair(t *testing.T) (certificate *x509.Certificate, privateKey *rsa.PrivateKey) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatalf("unable to create RSA private key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("unable to create x509 certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("unable to parse DER certificate: %v", err)
	}
	return cert, privateKey
}

func TestCreateAndVerify(t *testing.T) {
	cert, privateKey := keyPair(t)
	input := []byte("input_data")

	// Sign the signature
	sig, err := Sign(privateKey, input)
	if err != nil {
		t.Fatalf("unable to sign signature: %v", err)
	}
	// Verify the signature
	err = Verify(cert, input, sig)
	if err != nil {
		t.Errorf("unable to verify signature: %v", err)
	}
}
