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
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"testing"
	"time"
)

type testSigner struct {
	pub    crypto.PublicKey
	signFn func(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)
}

func (s *testSigner) Public() crypto.PublicKey {
	return s.pub
}

func (s *testSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.signFn(rand, digest, opts)
}

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
	sig, err := Sign(key, input)
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
	sig, err := Sign(key, input)
	if err != nil {
		t.Fatalf("unable to sign signature: %v", err)
	}
	// Verify the signature
	err = Verify(cert, input, sig)
	if err != nil {
		t.Errorf("unable to verify signature: %v", err)
	}
}

func TestSignErrors(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("unable to generate RSA key: %v", err)
	}
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("unable to generate Ed25519 key: %v", err)
	}

	tests := []struct {
		name string
		priv crypto.PrivateKey
	}{
		{
			name: "nil_private_key",
			priv: nil,
		},
		{
			name: "non_signer_private_key",
			priv: "not_a_signer",
		},
		{
			name: "unsupported_ed25519_key",
			priv: edPriv,
		},
		{
			name: "signer_failure",
			priv: &testSigner{
				pub: &rsaKey.PublicKey,
				signFn: func(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
					return nil, errors.New("sign failure")
				},
			},
		},
	}

	input := []byte("input_data")
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sig, err := Sign(tc.priv, input)
			if err == nil {
				t.Errorf("Sign(%T, %q) = (%x, nil), want non-nil error", tc.priv, input, sig)
			}
		})
	}
}

func TestVerifyErrors(t *testing.T) {
	input := []byte("input_data")

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("unable to generate RSA key: %v", err)
	}
	rsaCert := newCertificateAuthority(t, rsaKey, &rsaKey.PublicKey)
	rsaSig, err := Sign(rsaKey, input)
	if err != nil {
		t.Fatalf("unable to sign with RSA key: %v", err)
	}

	otherRSAKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("unable to generate second RSA key: %v", err)
	}
	otherRSACert := newCertificateAuthority(t, otherRSAKey, &otherRSAKey.PublicKey)

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("unable to generate ECDSA key: %v", err)
	}
	ecdsaCert := newCertificateAuthority(t, ecdsaKey, &ecdsaKey.PublicKey)
	ecdsaSig, err := Sign(ecdsaKey, input)
	if err != nil {
		t.Fatalf("unable to sign with ECDSA key: %v", err)
	}

	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("unable to generate Ed25519 key: %v", err)
	}
	edCert := newCertificateAuthority(t, edPriv, edPub)

	tests := []struct {
		name  string
		cert  *x509.Certificate
		input []byte
		sig   []byte
	}{
		{
			name:  "nil_certificate",
			cert:  nil,
			input: input,
			sig:   rsaSig,
		},
		{
			name:  "unsupported_ed25519_public_key",
			cert:  edCert,
			input: input,
			sig:   []byte("signature"),
		},
		{
			name:  "invalid_rsa_signature",
			cert:  rsaCert,
			input: input,
			sig:   []byte("invalid_signature"),
		},
		{
			name:  "tampered_rsa_input",
			cert:  rsaCert,
			input: []byte("tampered_data"),
			sig:   rsaSig,
		},
		{
			name:  "mismatched_rsa_certificate",
			cert:  otherRSACert,
			input: input,
			sig:   rsaSig,
		},
		{
			name:  "invalid_ecdsa_signature",
			cert:  ecdsaCert,
			input: input,
			sig:   []byte("invalid_signature"),
		},
		{
			name:  "tampered_ecdsa_input",
			cert:  ecdsaCert,
			input: []byte("tampered_data"),
			sig:   ecdsaSig,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := Verify(tc.cert, tc.input, tc.sig); err == nil {
				t.Errorf("Verify(cert, %q, %x) = nil, want non-nil error", tc.input, tc.sig)
			}
		})
	}
}
