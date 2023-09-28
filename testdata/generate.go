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

// This binary creates all the necessary certificates and private keys required for the Bootz emulator.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	log "github.com/golang/glog"
	ownershipvoucher "github.com/openconfig/bootz/common/ownership_voucher"
)

var (
	vendor             = flag.String("vendor", "", "The name of the vendor to generate self-signed certificates for.")
	owner              = flag.String("owner", "", "The name of the organization that owns the emulated device.")
	controlCardSerials = flag.String("serials", "", "Comma-separated list of control card serials to generate OVs for.")
)

const (
	// Default values for the Root CA certificates.
	caCountry  = "US"
	caProvince = "CA"
	caLocality = "Mountain View"
)

// newCertificateAuthority creates a new CA for the chosen organization.
// It returns a self-signed CA certificate as the first value, the associated private key as the second and any error as the third.
func newCertificateAuthority(commonName string, org string) (*x509.Certificate, *rsa.PrivateKey, error) {
	// Create the certificate authority.
	ca := &x509.Certificate{
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

// pemEncode returns a PEM encoding of DER bytes
func pemEncode(der []byte, pemType string) ([]byte, error) {
	pemBytes := new(bytes.Buffer)
	if err := pem.Encode(pemBytes, &pem.Block{
		Type:  pemType,
		Bytes: der,
	}); err != nil {
		return nil, err
	}
	return pemBytes.Bytes(), nil
}

// writeFile writes the contents to a new file in the current directory.
func writeFile(contents []byte, filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := f.Write(contents)
	if err != nil {
		return err
	}
	fmt.Printf("Wrote %d bytes to %v\n", b, filename)
	return nil
}

func main() {
	flag.Parse()
	if *vendor == "" {
		log.Exitf("vendor flag must be set")
	}
	if *owner == "" {
		log.Exitf("owner flag must be set")
	}
	serials := strings.Split(*controlCardSerials, ",")
	if len(serials) == 0 {
		log.Exitf("no control card serial numbers provided")
	}

	// Generate vendor CA
	fmt.Printf("Generating %v Root CA cert and private key\n", *vendor)
	vendorCAPub, vendorCAPriv, err := newCertificateAuthority("Manufacturer Root CA", *vendor)
	if err != nil {
		log.Exitf("unable to generate vendor CA: %v", err)
	}
	vendorCACertPem, err := pemEncode(vendorCAPub.Raw, "CERTIFICATE")
	if err != nil {
		log.Exit(err)
	}
	if err := writeFile(vendorCACertPem, "vendorca_pub.pem"); err != nil {
		log.Exit(err)
	}
	vendorCAPrivPem, err := pemEncode(x509.MarshalPKCS1PrivateKey(vendorCAPriv), "RSA PRIVATE KEY")
	if err != nil {
		log.Exit(err)
	}
	if err := writeFile(vendorCAPrivPem, "vendorca_priv.pem"); err != nil {
		log.Exit(err)
	}

	// Generate PDC.
	fmt.Printf("Generating %v PDC cert and private key\n", *owner)
	pdc, pdcPriv, err := newCertificateAuthority("Device Owner PDC", *owner)
	if err != nil {
		log.Exitf("unable to generate PDC: %v", err)
	}
	pdcPem, err := pemEncode(pdc.Raw, "CERTIFICATE")
	if err != nil {
		log.Exit(err)
	}
	if err := writeFile(pdcPem, "pdc_pub.pem"); err != nil {
		log.Exit(err)
	}
	pdcPrivPem, err := pemEncode(x509.MarshalPKCS1PrivateKey(pdcPriv), "RSA PRIVATE KEY")
	if err != nil {
		log.Exit(err)
	}
	if err := writeFile(pdcPrivPem, "pdc_priv.pem"); err != nil {
		log.Exit(err)
	}

	// For the purpose of this emulator, the OC is the same as the PDC.
	// Real implementations may instead have the OC as a separate certificate signed by the PDC.
	fmt.Printf("Generating %v OC cert and private key\n", *owner)
	oc, ocPriv := pdc, pdcPriv
	ocPem, err := pemEncode(oc.Raw, "CERTIFICATE")
	if err != nil {
		log.Exit(err)
	}
	if err := writeFile(ocPem, "oc_pub.pem"); err != nil {
		log.Exit(err)
	}
	ocPrivPem, err := pemEncode(x509.MarshalPKCS1PrivateKey(ocPriv), "RSA PRIVATE KEY")
	if err != nil {
		log.Exit(err)
	}
	if err := writeFile(ocPrivPem, "oc_priv.pem"); err != nil {
		log.Exit(err)
	}

	// Generate OVs for each control card.
	for _, s := range serials {
		fmt.Printf("Generating OV for control card serial %v\n", s)
		ov, err := ownershipvoucher.New(s, pdcPem, vendorCAPub, vendorCAPriv)
		if err != nil {
			log.Exitf("unable to create OV: %v", err)
		}
		ov64 := base64.StdEncoding.EncodeToString(ov)
		if err := writeFile([]byte(ov64), fmt.Sprintf("ov_%v.txt", s)); err != nil {
			log.Exit(err)
		}
	}

	// Generate a image file.
	if err := writeFile([]byte("ABCDEF"), "image.txt"); err != nil {
		log.Exit("Error when generating image file: %v", err)
	}
}
