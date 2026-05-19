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

// Package ownershipvoucher provides helper functions for generating, parsing and verifying ownership vouchers.
package ownershipvoucher

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"time"

	"go.mozilla.org/pkcs7"
)

// OwnershipVoucher defines the ownership voucher. See https://www.rfc-editor.org/rfc/rfc8366.html.
type OwnershipVoucher struct {
	OV OVInner `json:"ietf-voucher:voucher"`
}

// OVInner defines the ownership voucher inner structure.
type OVInner struct {
	XMLName                    xml.Name `xml:"voucher"`
	CreatedOn                  string   `json:"created-on" xml:"created-on"`
	ExpiresOn                  string   `json:"expires-on" xml:"expires-on"`
	Assertion                  string   `json:"assertion" xml:"assertion"`
	SerialNumber               string   `json:"serial-number" xml:"serial-number"`
	PinnedDomainCert           []byte   `json:"pinned-domain-cert" xml:"pinned-domain-cert"`
	DomainCertRevocationChecks bool     `json:"domain-cert-revocation-checks" xml:"domain-cert-revocation-checks"`
}

// Unmarshal unmarshals the contents of an ownership voucher. If a certPool is provided, it is used to verify the contents.
func Unmarshal(in []byte, certPool *x509.CertPool) (*OwnershipVoucher, error) {
	if len(in) == 0 {
		return nil, fmt.Errorf("ownership voucher is empty")
	}
	p7, err := pkcs7.Parse(in)
	if err != nil {
		return nil, fmt.Errorf("unable to parse into pkcs7 format: %v", err)
	}
	ov := &OwnershipVoucher{}
	jsonErr := json.Unmarshal(p7.Content, ov)
	if jsonErr != nil {
		xmlErr := xml.Unmarshal(p7.Content, &ov.OV)
		if xmlErr != nil {
			return nil, fmt.Errorf("failed unmarshalling ownership voucher in json or xml format: json err: %v, xml err: %v", jsonErr, xmlErr)
		}
	}
	if certPool != nil {
		if err = p7.VerifyWithChain(certPool); err != nil {
			return nil, fmt.Errorf("failed to verify ownership voucher: %v", err)
		}
	}
	return ov, nil
}

// NewOwnershipVoucher generates an ownership voucher signed by the vendor certificate.
func NewOwnershipVoucher(encoding string, deviceSerial string, pdc, vendorCert *x509.Certificate, vendorKey crypto.PrivateKey) ([]byte, error) {
	ov := &OwnershipVoucher{
		OV: OVInner{
			CreatedOn:        time.Now().Format(time.RFC3339),
			ExpiresOn:        time.Now().AddDate(999, 0, 0).Format(time.RFC3339),
			Assertion:        "verified",
			SerialNumber:     deviceSerial,
			PinnedDomainCert: pdc.Raw,
		},
	}
	var ovBytes []byte
	var err error
	switch encoding {
	case "json":
		if ovBytes, err = json.Marshal(ov); err != nil {
			return nil, err
		}
	case "xml":
		if ovBytes, err = xml.Marshal(ov.OV); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported encoding: %v", encoding)
	}
	signedMessage, err := pkcs7.NewSignedData(ovBytes)
	if err != nil {
		return nil, err
	}
	// Override the default SHA1 digest with SHA256.
	signedMessage.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	if err = signedMessage.AddSigner(vendorCert, vendorKey, pkcs7.SignerInfoConfig{}); err != nil {
		return nil, err
	}
	return signedMessage.Finish()
}
