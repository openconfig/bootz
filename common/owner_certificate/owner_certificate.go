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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"time"

	"go.mozilla.org/pkcs7"
)

// Verify checks that the provided CMS message is signed by a signer in the provided certPool and returns the signer certificate.
func Verify(in []byte, certPool *x509.CertPool) (*x509.Certificate, error) {
	if len(in) == 0 {
		return nil, fmt.Errorf("input CMS message is empty")
	}
	p7, err := pkcs7.Parse(in)
	if err != nil {
		return nil, fmt.Errorf("unable to parse into pkcs7 format: %v", err)
	}
	if len(p7.Certificates) == 0 {
		return nil, fmt.Errorf("no certificates found in pkcs7 message")
	}
	if err = p7.VerifyWithChain(certPool); err != nil {
		return nil, fmt.Errorf("failed to verify the chain of trust: %v", err)
	}
	return p7.Certificates[0], nil
}

// GenerateCMS takes an owner certificate keypair and converts it to a CMS message.
// The CMS message contains the owner certificate in its list of certificates.
func GenerateCMS(cert *x509.Certificate, priv crypto.PrivateKey) ([]byte, error) {
	signedMessage, err := pkcs7.NewSignedData(nil)
	if err != nil {
		return nil, err
	}
	// Override the default SHA1 digest with SHA256.
	signedMessage.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	signedMessage.AddCertificate(cert)

	err = signedMessage.AddSigner(cert, priv, pkcs7.SignerInfoConfig{})
	if err != nil {
		return nil, err
	}

	return signedMessage.Finish()
}

// NewRSACertificate creates a new RSA certificate and its private key, signed by the given certificate authority.
// If certificate authority is not provided, this new certificate will be created as a certificate authority instead.
func NewRSACertificate(commonName, deviceSerial string, caCert *x509.Certificate, caKey crypto.PrivateKey) (*x509.Certificate, *rsa.PrivateKey, error) {
	isCA := false
	if caCert == nil || caKey == nil {
		isCA = true
	}
	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(999, 0, 0),
		IsCA:                  isCA,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if deviceSerial != "" {
		template.Subject.SerialNumber = deviceSerial
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	if isCA {
		caCert = template
		caKey = key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}
