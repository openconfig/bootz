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
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"fmt"
)

// computeHash computes the hash of the input data using the provided signature algorithm, plus the
// crypto hash function that should be used to compute the signature.
func computeHash(algorithm x509.SignatureAlgorithm, input []byte) (crypto.Hash, []byte, error) {
	switch algorithm {
	case x509.ECDSAWithSHA384:
		v := sha512.Sum384(input)
		return crypto.SHA384, v[:], nil
	case x509.SHA256WithRSA:
		v := sha256.Sum256(input)
		return crypto.SHA256, v[:], nil
	default:
		return 0, nil, fmt.Errorf("computeHash(): unsupported signature algorithm: %v", algorithm)
	}
}

// Sign generates a base64-encoded signature of the input data using the provided private key.
func Sign(privateKey crypto.PrivateKey, algorithm x509.SignatureAlgorithm, input []byte) (string, error) {
	hashAlgo, hashed, err := computeHash(algorithm, input)
	if err != nil {
		return "", err
	}
	var sig []byte
	switch priv := privateKey.(type) {
	case *rsa.PrivateKey:
		sig, err = rsa.SignPKCS1v15(rand.Reader, priv, hashAlgo, hashed)
		if err != nil {
			return "", fmt.Errorf("Sign(): unable to sign signature: %w", err)
		}
	case *ecdsa.PrivateKey:
		sig, err = ecdsa.SignASN1(rand.Reader, priv, hashed)
		if err != nil {
			return "", fmt.Errorf("Sign(): unable to sign signature: %w", err)
		}
	default:
		return "", fmt.Errorf("Sign(): unsupported private key type: %T", priv)
	}

	return base64.StdEncoding.EncodeToString(sig), nil
}

// Verify verifies a base64-encoded signature of the input data using the provided certificate.
func Verify(cert *x509.Certificate, input []byte, signature string) error {
	decodedSig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("Verify(): unable to base64 decode: %w", err)
	}
	hashAlgo, hashed, err := computeHash(cert.SignatureAlgorithm, input)
	if err != nil {
		return err
	}

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		err = rsa.VerifyPKCS1v15(pub, hashAlgo, hashed, decodedSig)
		if err != nil {
			return fmt.Errorf("Verify(): signature not verified: %w", err)
		}
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, hashed, decodedSig) {
			return fmt.Errorf("Verify(): signature not verified")
		}
	default:
		return fmt.Errorf("Verify(): unsupported public key type: %T", pub)
	}
	return nil
}
