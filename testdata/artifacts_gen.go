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
	"github.com/openconfig/bootz/server/service"
)

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
