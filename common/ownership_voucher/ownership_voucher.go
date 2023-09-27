// Package ownershipvoucher provides helper functions for generating, parsing and verifying ownership vouchers.
package ownershipvoucher

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"go.mozilla.org/pkcs7"
)

const (
	ovExpiry = time.Hour * 24 * 365
)

// OwnershipVoucher wraps OwnershipVoucherInner.
type OwnershipVoucher struct {
	OV OwnershipVoucherInner `json:"ietf-voucher:voucher"`
}

// OwnershipVoucherInner defines the Ownership Voucher format. See https://www.rfc-editor.org/rfc/rfc8366.html.
type OwnershipVoucherInner struct {
	CreatedOn                  string `json:"created-on"`
	ExpiresOn                  string `json:"expires-on"`
	SerialNumber               string `json:"serial-number"`
	Assertion                  string `json:"assertion"`
	PinnedDomainCert           string `json:"pinned-domain-cert"`
	DomainCertRevocationChecks bool   `json:"domain-cert-revocation-checks"`
}

// removePemHeaders strips the PEM headers from a certificate so it can be used in an Ownership Voucher.
func RemovePemHeaders(pemBlock string) string {
	pemBlock = strings.TrimPrefix(pemBlock, "-----BEGIN CERTIFICATE-----\n")
	pemBlock = strings.TrimSuffix(pemBlock, "\n-----END CERTIFICATE-----\n")
	return pemBlock
}

// VerifyAndUnmarshal unmarshals the contents of an Ownership Voucher
// and verifies that it has been signed by a signer in the given cert pool.
func VerifyAndUmarshal(in []byte, certPool *x509.CertPool) (*OwnershipVoucher, error) {
	if len(in) == 0 {
		return nil, fmt.Errorf("ownership voucher is empty")
	}
	p7, err := pkcs7.Parse(in)
	if err != nil {
		return nil, fmt.Errorf("unable to parse into pkcs7 format: %v", err)
	}
	ov := OwnershipVoucher{}
	err = json.Unmarshal(p7.Content, &ov)
	if err != nil {
		return nil, fmt.Errorf("failed unmarshaling ownership voucher: %v", err)
	}
	if err = p7.VerifyWithChain(certPool); err != nil {
		return nil, fmt.Errorf("failed to verify OV: %v", err)
	}
	return &ov, nil
}

// New generates an Ownership Voucher which is signed by the vendor's CA.
func New(serial string, pdcPem []byte, vendorCACert *x509.Certificate, vendorCAPriv *rsa.PrivateKey) ([]byte, error) {
	currentTime := time.Now()
	ov := OwnershipVoucher{
		OV: OwnershipVoucherInner{
			CreatedOn:        currentTime.String(),
			ExpiresOn:        currentTime.Add(ovExpiry).String(),
			SerialNumber:     serial,
			PinnedDomainCert: RemovePemHeaders(string(pdcPem)),
		},
	}

	ovBytes, err := json.Marshal(ov)
	if err != nil {
		return nil, err
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
