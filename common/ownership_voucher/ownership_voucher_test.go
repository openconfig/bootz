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

package ownershipvoucher

import (
	"bytes"
	"crypto/x509"
	"testing"

	artifacts "github.com/openconfig/bootz/testdata"
)

var (
	wantSerial = "123A"
)

// Tests that a new OV can be created and it can be unpacked and verified.
func TestEndToEndJSON(t *testing.T) {
	pdc, _, err := artifacts.NewCertificateAuthority("Pinned Domain Cert", "Google", "localhost")
	if err != nil {
		t.Fatalf("unable to generate PDC: %v", err)
	}
	vendorca, vendorcaPrivateKey, err := artifacts.NewCertificateAuthority("Cisco Certificate Authority", "Cisco", "localhost")
	if err != nil {
		t.Fatalf("unable to generate Vendor CA: %v", err)
	}

	ov, err := artifacts.NewOwnershipVoucher("json", wantSerial, pdc, vendorca, vendorcaPrivateKey)
	if err != nil {
		t.Errorf("New err = %v, want nil", err)
	}

	vendorCAPool := x509.NewCertPool()
	vendorCAPool.AddCert(vendorca)

	got, err := Unmarshal(ov, vendorCAPool)
	if err != nil {
		t.Errorf("VerifyAndUnmarshal err = %v, want nil", err)
	}

	if !bytes.Equal(got.OV.PinnedDomainCert, pdc.Raw) {
		t.Errorf("got PDC = %v, want %v", got.OV.PinnedDomainCert, pdc.Raw)
	}
	if gotSerial := got.OV.SerialNumber; gotSerial != wantSerial {
		t.Errorf("got serial = %v, want %v", gotSerial, wantSerial)
	}
}

func TestEndToEndXML(t *testing.T) {
	pdc, _, err := artifacts.NewCertificateAuthority("Pinned Domain Cert", "Google", "localhost")
	if err != nil {
		t.Fatalf("unable to generate PDC: %v", err)
	}
	vendorca, vendorcaPrivateKey, err := artifacts.NewCertificateAuthority("Cisco Certificate Authority", "Cisco", "localhost")
	if err != nil {
		t.Fatalf("unable to generate Vendor CA: %v", err)
	}

	ov, err := artifacts.NewOwnershipVoucher("xml", wantSerial, pdc, vendorca, vendorcaPrivateKey)
	if err != nil {
		t.Errorf("New err = %v, want nil", err)
	}

	vendorCAPool := x509.NewCertPool()
	vendorCAPool.AddCert(vendorca)

	got, err := Unmarshal(ov, vendorCAPool)
	if err != nil {
		t.Errorf("VerifyAndUnmarshal err = %v, want nil", err)
	}
	// Don't check the PDC here as XML encoding doesn't nicely encode it in base64 as json does.
	// All we really care about is the serial number anyway.
	if gotSerial := got.OV.SerialNumber; gotSerial != wantSerial {
		t.Errorf("got serial = %v, want %v", gotSerial, wantSerial)
	}
}
