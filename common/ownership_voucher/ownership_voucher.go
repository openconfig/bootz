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
	"crypto/x509"
	"encoding/json"
	"encoding/xml"
	"fmt"

	"go.mozilla.org/pkcs7"

	artifacts "github.com/openconfig/bootz/testdata"
)

// Unmarshal unmarshals the contents of an Ownership Voucher. If a certPool is provided,
// it is used to verify the contents.
func Unmarshal(in []byte, certPool *x509.CertPool) (*artifacts.OwnershipVoucher, error) {
	if len(in) == 0 {
		return nil, fmt.Errorf("ownership voucher is empty")
	}
	p7, err := pkcs7.Parse(in)
	if err != nil {
		return nil, fmt.Errorf("unable to parse into pkcs7 format: %v", err)
	}
	ov := artifacts.OwnershipVoucher{}
	jsonErr := json.Unmarshal(p7.Content, &ov)
	if jsonErr != nil {
		xmlErr := xml.Unmarshal(p7.Content, &ov.OV)
		if xmlErr != nil {
			return nil, fmt.Errorf("failed unmarshalling ownership voucher in json or xml format: json err: %v, xml err: %v", jsonErr, xmlErr)
		}
	}
	if certPool != nil {
		if err = p7.VerifyWithChain(certPool); err != nil {
			return nil, fmt.Errorf("failed to verify OV: %v", err)
		}
	}
	return &ov, nil
}
