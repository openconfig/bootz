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

// Package artifactmanager is an artifact manager that manages artifacts like certificates and keys.
// The implementation here is an in-memory implementation primarily used for testing and qualification.
// For production usecase, you should replace this implementation with your own one.
package artifactmanager

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"

	ownershipvoucher "github.com/openconfig/bootz/common/ownership_voucher"

	epb "github.com/openconfig/attestz/proto/tpm_enrollz"
	cpb "github.com/openconfig/bootz/server/proto/config"
)

// InMemoryArtifactManager provides a simple in memory handler for artifacts.
type InMemoryArtifactManager struct {
	trustAnchorCert *x509.Certificate
	trustAnchorKey  crypto.PrivateKey
	ownerCert       *x509.Certificate
	ownerKey        crypto.PrivateKey
	vendorCAPool    *x509.CertPool
	controlCards    map[string]*cpb.ControlCard
}

// BootzServerTrustAnchorKeyPair returns the Bootz server trust anchor. This is the keypair that will generate the server's TLS certificate.
func (m *InMemoryArtifactManager) BootzServerTrustAnchorKeyPair() (*x509.Certificate, crypto.PrivateKey) {
	return m.trustAnchorCert, m.trustAnchorKey
}

// OwnerCertificateKeyPair returns the owner certificate keypair for signing the bootstrap response.
func (m *InMemoryArtifactManager) OwnerCertificateKeyPair() (*x509.Certificate, crypto.PrivateKey) {
	return m.ownerCert, m.ownerKey
}

// OwnershipVoucher returns the ownership voucher for the given serial number and vendor.
func (m *InMemoryArtifactManager) OwnershipVoucher(ctx context.Context, serial string, vendor string) ([]byte, error) {
	// We don't use the "vendor" argument because it is empty when the request is a ReportStatusRequest.
	// For simplicity, we assume the serial numbers are unique within our inventory.
	// For production usecase, you should maintain a list containing only the chassis that are being bootstrappped and match to that list to prevent serial number collision.
	if v, ok := m.controlCards[serial]; ok {
		ov, err := base64.StdEncoding.DecodeString(v.GetOwnershipVoucher())
		if err != nil {
			return nil, fmt.Errorf("base64 decoding failed: %v", err)
		}
		unmarshaled, err := ownershipvoucher.Unmarshal(ov, m.vendorCAPool)
		if err != nil {
			return nil, fmt.Errorf("unmarshalling failed: %v", err)
		}
		if !strings.EqualFold(unmarshaled.OV.SerialNumber, serial) {
			return nil, fmt.Errorf("serial number does not match, got %v, want %v", unmarshaled.OV.SerialNumber, serial)
		}
		return ov, nil
	}
	return nil, fmt.Errorf("not found for serial number: %v", serial)
}

// PublicKey retrieves the EK or PPK public key of the chassis for use in the BootstrapStream challenge.
func (m *InMemoryArtifactManager) PublicKey(ctx context.Context, serial string, vendor string) (crypto.PublicKey, epb.Key, error) {
	// We don't use the "vendor" argument because it is empty when the request is a ReportStatusRequest.
	// For simplicity, we assume the serial numbers are unique within our inventory.
	// For production usecase, you should maintain a list containing only the chassis that are being bootstrappped and match to that list to prevent serial number collision.
	if v, ok := m.controlCards[serial]; ok {
		pubBytes, err := base64.StdEncoding.DecodeString(v.GetPublicKey())
		if err != nil {
			return nil, epb.Key_KEY_UNSPECIFIED, fmt.Errorf("failed to decode public key: %v", err)
		}
		pub, err := x509.ParsePKIXPublicKey(pubBytes)
		if err != nil {
			return nil, epb.Key_KEY_UNSPECIFIED, fmt.Errorf("failed to parse public key: %v", err)
		}
		return pub, v.GetPublicKeyType(), nil
	}
	return nil, epb.Key_KEY_UNSPECIFIED, fmt.Errorf("public key not found for serial number: %v", serial)
}

// VendorCABundle returns the pool of certificates that the server should use to validate the provided IDevID certificates.
func (m *InMemoryArtifactManager) VendorCABundle() *x509.CertPool {
	return m.vendorCAPool
}

func parseCertKeyPair(pair *cpb.CertKeyPair) (*x509.Certificate, crypto.PrivateKey, error) {
	if pair == nil {
		return nil, nil, fmt.Errorf("certificate key pair is nil")
	}
	certBytes, err := base64.StdEncoding.DecodeString(pair.GetCert())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode certificate: %v", err)
	}
	keyBytes, err := base64.StdEncoding.DecodeString(pair.GetKey())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode private key: %v", err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %v", err)
	}
	key, err := x509.ParsePKCS8PrivateKey(keyBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse private key: %v", err)
	}
	return cert, key, nil
}

// New returns a new in-memory artifact manager.
func New(config *cpb.Config) (*InMemoryArtifactManager, error) {
	var err error
	am := &InMemoryArtifactManager{}
	am.trustAnchorCert, am.trustAnchorKey, err = parseCertKeyPair(config.GetTrustAnchor())
	if err != nil {
		return nil, fmt.Errorf("trust anchor error: %v", err)
	}
	am.ownerCert, am.ownerKey, err = parseCertKeyPair(config.GetOwnerCertificate())
	if err != nil {
		return nil, fmt.Errorf("owner certificate error: %v", err)
	}
	am.vendorCAPool = x509.NewCertPool()
	for _, v := range config.GetVendorCaCerts() {
		certBytes, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("failed to decode vendor CA certificate: %v", err)
		}
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse vendor CA certificate: %v", err)
		}
		am.vendorCAPool.AddCert(cert)
	}
	am.controlCards = make(map[string]*cpb.ControlCard)
	for _, c := range config.GetChassis() {
		for _, cc := range c.GetControlCards() {
			am.controlCards[cc.GetSerialNumber()] = cc
		}
	}
	return am, nil
}
