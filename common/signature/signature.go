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

// Package signature provides methods to sign and verify signatures.
package signature

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
)

// HashAlgorithmForPublicKey maps a public key algorithm to a hash algorithm.
// This mapping is explicitly defined as part of Bootz specification.
func HashAlgorithmForPublicKey(pub crypto.PublicKey) (crypto.Hash, error) {
	switch pub.(type) {
	case *rsa.PublicKey:
		return crypto.SHA256, nil
	case *ecdsa.PublicKey:
		return crypto.SHA384, nil
	default:
		return 0, fmt.Errorf("unsupported public key type: %T", pub)
	}
}

// Sign generates a signature of the input data using the provided private key.
func Sign(privateKey crypto.PrivateKey, input []byte) ([]byte, error) {
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("Sign(): private key does not implement crypto.Signer")
	}
	hashAlgo, err := HashAlgorithmForPublicKey(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("Sign(): failed to deduce hash algorithm for public key: %w", err)
	}
	sig, err := crypto.SignMessage(signer, rand.Reader, input, hashAlgo)
	if err != nil {
		return nil, fmt.Errorf("Sign(): failed to sign data: %w", err)
	}
	return sig, nil
}

// Verify verifies a signature of the input data using the provided certificate.
func Verify(cert *x509.Certificate, input []byte, signature []byte) error {
	if cert == nil {
		return fmt.Errorf("Verify(): certificate is nil")
	}
	hashAlgo, err := HashAlgorithmForPublicKey(cert.PublicKey)
	if err != nil {
		return fmt.Errorf("Verify(): failed to deduce hash algorithm for public key: %w", err)
	}
	h := hashAlgo.New()
	h.Write(input)
	digest := h.Sum(nil)

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(pub, hashAlgo, digest, signature); err != nil {
			return fmt.Errorf("Verify(): signature not verified: %w", err)
		}
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, digest, signature) {
			return fmt.Errorf("Verify(): signature not verified")
		}
	default:
		return fmt.Errorf("Verify(): unsupported public key type: %T", pub)
	}
	return nil
}
