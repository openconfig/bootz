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

// Package ownercertificate provides helper functions for generating, parsing and verifying owner certs.
package ownercertificate

import (
	"crypto"
	"crypto/x509"
	"fmt"

	"go.mozilla.org/pkcs7"
)

// Verify checks that the provided CMS value is signed by a signer in the provided
// certPool and returns the Ownership Certificate.
func Verify(in []byte, certPool *x509.CertPool) (*x509.Certificate, error) {
	if len(in) == 0 {
		return nil, fmt.Errorf("owner certificate is empty")
	}
	p7, err := pkcs7.Parse(in)
	if err != nil {
		return nil, fmt.Errorf("unable to parse into pkcs7 format: %v", err)
	}
	if err = p7.VerifyWithChain(certPool); err != nil {
		return nil, fmt.Errorf("failed to verify OC: %v", err)
	}
	if len(p7.Certificates) == 0 {
		return nil, fmt.Errorf("no certificates found in pkcs7 message")
	}
	return p7.Certificates[0], nil
}

// GenerateCMS takes an Ownership Certificate keypair and converts it to a CMS structure.
// The returned CMS object is the DER-encoded Owner Certificate.
func GenerateCMS(cert *x509.Certificate, priv crypto.PrivateKey) ([]byte, error) {
	signedMessage, err := pkcs7.NewSignedData(nil)
	if err != nil {
		return nil, err
	}
	signedMessage.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	signedMessage.SetEncryptionAlgorithm(pkcs7.OIDEncryptionAlgorithmRSA)
	signedMessage.AddCertificate(cert)

	err = signedMessage.AddSigner(cert, priv, pkcs7.SignerInfoConfig{})
	if err != nil {
		return nil, err
	}

	return signedMessage.Finish()
}
