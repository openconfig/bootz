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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func newCertificateAuthority(t *testing.T, priv crypto.PrivateKey, pub crypto.PublicKey) *x509.Certificate {
	t.Helper()
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(int64(time.Now().Year())),
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// Generate the self-signed cert.
	certBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, priv)
	if err != nil {
		t.Fatalf("unable to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("unable to parse certificate: %v", err)
	}
	return cert
}

func TestCreateAndVerifyRSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatalf("unable to generate test key: %v", err)
	}
	cert := newCertificateAuthority(t, key, &key.PublicKey)
	input := []byte("input_data")

	// Sign the signature
	sig, err := Sign(key, cert.SignatureAlgorithm, input)
	if err != nil {
		t.Fatalf("unable to sign signature: %v", err)
	}
	// Verify the signature
	err = Verify(cert, input, sig)
	if err != nil {
		t.Errorf("unable to verify signature: %v", err)
	}
}

func TestCreateAndVerifyECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("unable to generate test key: %v", err)
	}
	cert := newCertificateAuthority(t, key, &key.PublicKey)
	input := []byte("input_data")

	// Sign the signature
	sig, err := Sign(key, cert.SignatureAlgorithm, input)
	if err != nil {
		t.Fatalf("unable to sign signature: %v", err)
	}
	// Verify the signature
	err = Verify(cert, input, sig)
	if err != nil {
		t.Errorf("unable to verify signature: %v", err)
	}
}
