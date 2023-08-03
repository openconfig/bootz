// This binary creates all the necessary certificates and private keys required for the Bootz emulator.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	log "github.com/golang/glog"
	"go.mozilla.org/pkcs7"
)

var (
	vendor             = flag.String("vendor", "", "The name of the vendor to generate self-signed certificates for.")
	owner              = flag.String("owner", "", "The name of the organization that owns the emulated device.")
	controlCardSerials = flag.String("serials", "", "Comma-separated list of control card serials to generate OVs for.")
)

type OwnershipVoucher struct {
	OV OwnershipVoucherInner `json:"ietf-voucher:voucher"`
}

// Defines the Ownership Voucher format. See https://www.rfc-editor.org/rfc/rfc8366.html.
type OwnershipVoucherInner struct {
	CreatedOn                  string `json:"created-on"`
	ExpiresOn                  string `json:"expires-on"`
	SerialNumber               string `json:"serial-number"`
	Assertion                  string `json:"assertion"`
	PinnedDomainCert           string `json:"pinned-domain-cert"`
	DomainCertRevocationChecks bool   `json:"domain-cert-revocation-checks"`
}

// certFromPem converts a PEM-formatted byte slice to an x509 Certificate
func certFromPem(contents []byte) (*x509.Certificate, error) {
	pemBlock, _ := pem.Decode(contents)
	return x509.ParseCertificate(pemBlock.Bytes)
}

// privateKeyFromPem converts a PEM-formatted byte slice to an RSA Private Key
func privateKeyFromPem(contents []byte) (*rsa.PrivateKey, error) {
	pemBlock, _ := pem.Decode(contents)
	return x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
}

// newCertificateAuthority creates a new CA for the chosen organization.
// It returns a self-signed CA certificate as the first value, the associated private key as the second and any error as the third.
func newCertificateAuthority(commonName string, org string) (string, string, error) {
	// Create the certificate authority.
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(int64(time.Now().Year())),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{org},
			Country:      []string{"US"},
			Province:     []string{"CA"},
			Locality:     []string{"Mountain View"},
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
		return "", "", err
	}
	// Generate the self-signed cert.
	certBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		return "", "", err
	}
	// Encode certificate in PEM format.
	caCertPEM := new(bytes.Buffer)
	if err = pem.Encode(caCertPEM, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}); err != nil {
		return "", "", err
	}

	// Encode private key in PEM format.
	caPrivateKeyPEM := new(bytes.Buffer)
	if err := pem.Encode(caPrivateKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivateKey),
	}); err != nil {
		return "", "", err
	}

	return caCertPEM.String(), caPrivateKeyPEM.String(), nil
}

// removePemHeaders strips the PEM headers from a certificate so it can be used in an Ownership Voucher.
func removePemHeaders(pemBlock string) string {
	pemBlock = strings.TrimPrefix(pemBlock, "-----BEGIN CERTIFICATE-----\n")
	pemBlock = strings.TrimSuffix(pemBlock, "\n-----END CERTIFICATE-----\n")
	return pemBlock
}

// newOwnershipVoucher creates an OV for the device serial which is signed by the vendor's CA.
func newOwnershipVoucher(serial string, pdcPem []byte, vendorCACert *x509.Certificate, vendorCAPriv *rsa.PrivateKey) (string, error) {
	ov := OwnershipVoucher{
		OV: OwnershipVoucherInner{
			CreatedOn:        time.Now().String(),
			ExpiresOn:        time.Now().Add(time.Hour * 24 * 365).String(),
			SerialNumber:     serial,
			PinnedDomainCert: removePemHeaders(string(pdcPem)),
		},
	}

	ovBytes, err := json.Marshal(ov)
	if err != nil {
		return "", err
	}

	signedMessage, err := pkcs7.NewSignedData(ovBytes)
	if err != nil {
		return "", err
	}
	signedMessage.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	signedMessage.SetEncryptionAlgorithm(pkcs7.OIDEncryptionAlgorithmRSA)

	err = signedMessage.AddSigner(vendorCACert, vendorCAPriv, pkcs7.SignerInfoConfig{})
	if err != nil {
		return "", err
	}

	signedBytes, err := signedMessage.Finish()
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(signedBytes), nil
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
	if err := writeFile([]byte(vendorCAPub), "vendorca_pub.pem"); err != nil {
		log.Exit(err)
	}
	if err := writeFile([]byte(vendorCAPriv), "vendorca_priv.pem"); err != nil {
		log.Exit(err)
	}

	//Generate PDC.
	fmt.Printf("Generating %v PDC cert and private key\n", *owner)
	pdc, pdcPriv, err := newCertificateAuthority("Device Owner PDC", *owner)
	if err != nil {
		log.Exitf("unable to generate PDC: %v", err)
	}
	if err := writeFile([]byte(pdc), "pdc_pub.pem"); err != nil {
		log.Exit(err)
	}
	if err := writeFile([]byte(pdcPriv), "pdc_priv.pem"); err != nil {
		log.Exit(err)
	}

	// For the purpose of this emulator, the OC is the same as the PDC.
	// Real implementations may instead have the OC as a separate certificate signed by the PDC.
	fmt.Printf("Generating %v OC cert and private key\n", *owner)
	oc, ocPriv := pdc, pdcPriv
	if err := writeFile([]byte(oc), "oc_pub.pem"); err != nil {
		log.Exit(err)
	}
	if err := writeFile([]byte(ocPriv), "oc_priv.pem"); err != nil {
		log.Exit(err)
	}

	// Convert PEM bytes to RSA Private Key for signing the OV
	vcapriv, err := privateKeyFromPem([]byte(vendorCAPriv))
	if err != nil {
		log.Exit(err)
	}
	// Convert PEM bytes to x509 Cert for signing the OV
	vca, err := certFromPem([]byte(vendorCAPub))
	if err != nil {
		log.Exit(err)
	}

	// Generate OVs for each control card.
	for _, s := range serials {
		fmt.Printf("Generating OV for control card serial %v\n", s)
		ov, err := newOwnershipVoucher(s, []byte(pdc), vca, vcapriv)
		if err != nil {
			log.Exitf("unable to create OV: %v", err)
		}
		if err := writeFile([]byte(ov), fmt.Sprintf("ov_%v.txt", s)); err != nil {
			log.Exit(err)
		}
	}
}
