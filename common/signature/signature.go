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
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
)

// Sign generates a base64-encoded signature of the input data using the provided private key.
// The private key must be RSA.
func Sign(privateKey crypto.PrivateKey, input []byte) (string, error) {
	hashed := sha256.Sum256(input)
	var sig []byte
	var err error
	switch priv := privateKey.(type) {
	case *rsa.PrivateKey:
		sig, err = rsa.SignPKCS1v15(nil, priv, crypto.SHA256, hashed[:])
		if err != nil {
			return "", fmt.Errorf("Sign(): unable to sign signature: %w", err)
		}
	default:
		return "", fmt.Errorf("Verify(): unsupported private key type: %T", priv)
	}

	return base64.StdEncoding.EncodeToString(sig), nil
}

// Verify verifies a base64-encoded signature of the input data using the provided certificate.
// The certificate's public key must be RSA.
func Verify(cert *x509.Certificate, input []byte, signature string) error {
	decodedSig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("Verify(): unable to base64 decode: %w", err)
	}
	hashed := sha256.Sum256(input)
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed[:], decodedSig)
		if err != nil {
			return fmt.Errorf("Verify(): signature not verified: %w", err)
		}
	default:
		return fmt.Errorf("Verify(): unsupported public key type: %T", pub)
	}
	return nil
}
