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

// Package artifacts contains helper functions to generate x509/RSA Certificate KeyPairs.
package artifacts

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"math/big"
	"time"

	"github.com/openconfig/bootz/server/service"
	"go.mozilla.org/pkcs7"
)

const (
	// Default values for the Root CA certificates.
	caCountry  = "US"
	caProvince = "CA"
	caLocality = "Mountain View"
	ovExpiry   = time.Hour * 24 * 365
)

// OwnershipVoucher wraps Inner.
type OwnershipVoucher struct {
	OV Inner `json:"ietf-voucher:voucher" xml:"voucher"`
}

// Inner defines the Ownership Voucher format. See https://www.rfc-editor.org/rfc/rfc8366.html.
type Inner struct {
	XMLName                    xml.Name `xml:"voucher"`
	CreatedOn                  string   `json:"created-on" xml:"created-on"`
	ExpiresOn                  string   `json:"expires-on" xml:"expires-on"`
	SerialNumber               string   `json:"serial-number" xml:"serial-number"`
	Assertion                  string   `json:"assertion" xml:"assertion"`
	PinnedDomainCert           []byte   `json:"pinned-domain-cert" xml:"pinned-domain-cert"`
	DomainCertRevocationChecks bool     `json:"domain-cert-revocation-checks" xml:"domain-cert-revocation-checks"`
}

// NewCertificateAuthority creates a new self-signed CA for the chosen organization.
func NewCertificateAuthority(commonName, org, serverName string) (*x509.Certificate, *rsa.PrivateKey, error) {
	// Create the certificate authority.
	ca := &x509.Certificate{
		DNSNames:     []string{serverName},
		SerialNumber: big.NewInt(int64(time.Now().Year())),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{org},
			Country:      []string{caCountry},
			Province:     []string{caProvince},
			Locality:     []string{caLocality},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// Generate an RSA 4096 bit pub/private key pair.
	caPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}
	// Generate the self-signed cert.
	certBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, caPrivateKey, nil
}

// NewSignedCertificate creates a new cert/private keypair signed by the provided Certificate Authority.
func NewSignedCertificate(commonName, org, serverName string, ca *x509.Certificate, caPrivateKey crypto.PrivateKey) (*x509.Certificate, *rsa.PrivateKey, error) {
	// Create the certificate template. Geographic information is the same as the Certificate Authority by default.
	template := &x509.Certificate{
		DNSNames:     []string{serverName},
		SerialNumber: big.NewInt(int64(time.Now().Year())),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{org},
			Country:      []string{caCountry},
			Province:     []string{caProvince},
			Locality:     []string{caLocality},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, ca, &privateKey.PublicKey, caPrivateKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, err
	}
	return cert, privateKey, nil
}

// TLSCertificate creates a new TLS trust anchor for use with the server's gRPC connection.
func TLSCertificate(cert *x509.Certificate, privateKey *rsa.PrivateKey) (*tls.Certificate, error) {
	certPEM := new(bytes.Buffer)
	if err := pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}); err != nil {
		return nil, err
	}
	privateKeyDer := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := new(bytes.Buffer)
	if err := pem.Encode(privateKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyDer,
	}); err != nil {
		return nil, err
	}
	tlsCert, err := tls.X509KeyPair(certPEM.Bytes(), privateKeyPEM.Bytes())
	if err != nil {
		return nil, err
	}

	return &tlsCert, nil
}

// NewOwnershipVoucher generates an Ownership Voucher which is signed by the vendor's CA.
func NewOwnershipVoucher(encoding string, serial string, pdc, vendorCACert *x509.Certificate, vendorCAPriv crypto.PrivateKey) ([]byte, error) {
	currentTime := time.Now()
	ov := OwnershipVoucher{
		OV: Inner{
			CreatedOn:        currentTime.Format(time.RFC3339),
			ExpiresOn:        currentTime.Add(ovExpiry).Format(time.RFC3339),
			SerialNumber:     serial,
			PinnedDomainCert: pdc.Raw,
		},
	}

	var ovBytes []byte
	var err error
	switch encoding {
	case "json":
		ovBytes, err = json.Marshal(ov)
		if err != nil {
			return nil, err
		}
	case "xml":
		ovBytes, err = xml.Marshal(ov.OV)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported encoding: %v", encoding)
	}

	signedMessage, err := pkcs7.NewSignedData(ovBytes)
	if err != nil {
		return nil, err
	}
	signedMessage.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	signedMessage.SetEncryptionAlgorithm(pkcs7.OIDEncryptionAlgorithmRSA)

	err = signedMessage.AddSigner(vendorCACert, vendorCAPriv, pkcs7.SignerInfoConfig{})
	if err != nil {
		return nil, err
	}

	return signedMessage.Finish()
}

// GenerateSecurityArtifacts generates security artifacts.
func GenerateSecurityArtifacts(controlCardSerials []string, ownerOrg string, vendorOrg string) (*service.SecurityArtifacts, error) {
	pdc, pdcPrivateKey, err := NewCertificateAuthority("Pinned Domain Cert", ownerOrg, "localhost")
	if err != nil {
		return nil, err
	}
	oc, ocPrivateKey, err := NewSignedCertificate("Owner Certificate", ownerOrg, "localhost", pdc, pdcPrivateKey)
	if err != nil {
		return nil, err
	}
	vendorCA, vendorCAPrivateKey, err := NewCertificateAuthority("Vendor Certificate Authority", vendorOrg, "localhost")
	if err != nil {
		return nil, err
	}
	trustAnchor, trustAnchorPrivatekey, err := NewCertificateAuthority("Trust Anchor", ownerOrg, "localhost")
	if err != nil {
		return nil, err
	}
	ovs := service.OVList{}
	for _, serial := range controlCardSerials {
		ov, err := NewOwnershipVoucher("json", serial, pdc, vendorCA, vendorCAPrivateKey)
		if err != nil {
			return nil, err
		}
		ovs[serial] = ov
	}
	tlsTrustAnchor, err := TLSCertificate(trustAnchor, trustAnchorPrivatekey)
	if err != nil {
		return nil, err
	}

	return &service.SecurityArtifacts{
		TrustAnchor:           trustAnchor,
		TrustAnchorPrivateKey: trustAnchorPrivatekey,
		OwnerCert:             oc,
		OwnerCertPrivateKey:   ocPrivateKey,
		PDC:                   pdc,
		PDCPrivateKey:         pdcPrivateKey,
		VendorCA:              vendorCA,
		VendorCAPrivateKey:    vendorCAPrivateKey,
		OV:                    ovs,
		TLSKeypair:            tlsTrustAnchor,
	}, nil
}
