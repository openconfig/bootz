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
	"encoding/base64"
	"encoding/pem"
	"testing"

	_ "embed"
)

var (
	wantSerial = "123A"
	//go:embed testdata/ov_123A.txt
	testOV string
	//go:embed testdata/pdc_pub.pem
	pdcPub []byte
	//go:embed testdata/vendorca_pub.pem
	vendorCAPub []byte
	//go:embed testdata/vendorca_priv.pem
	vendorCAPriv []byte
)

// Tests that a new OV can be created and it can be unpacked and verified.
func TestNew(t *testing.T) {
	pubPEM, _ := pem.Decode(vendorCAPub)
	if pubPEM == nil {
		t.Fatal("could not decode Vendor CA Public key")
	}
	pubCert, err := x509.ParseCertificate(pubPEM.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	privPEM, _ := pem.Decode(vendorCAPriv)
	if privPEM == nil {
		t.Fatal("could not decode Vendor CA private key")
	}
	privKey, err := x509.ParsePKCS1PrivateKey(privPEM.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pdcDER, _ := pem.Decode(pdcPub)
	if pdcDER == nil {
		t.Fatalf("Could not decode PDC Cert")
	}

	got, err := New(wantSerial, pdcDER.Bytes, pubCert, privKey)
	if err != nil {
		t.Errorf("New err = %v, want nil", err)
	}

	vendorCAPool := x509.NewCertPool()
	if !vendorCAPool.AppendCertsFromPEM(vendorCAPub) {
		t.Fatalf("unable to add vendor root CA to pool")
	}

	_, err = VerifyAndUnmarshal(got, vendorCAPool)
	if err != nil {
		t.Errorf("VerifyAndUnmarshal err = %v, want nil", err)
	}
}

// Tests VerifyAndUnmarshal using a known good OV.
func TestVerifyAndUnmarshal(t *testing.T) {
	vendorCAPool := x509.NewCertPool()
	if !vendorCAPool.AppendCertsFromPEM(vendorCAPub) {
		t.Fatalf("unable to add vendor root CA to pool")
	}

	decodedOV, err := base64.StdEncoding.DecodeString(testOV)
	if err != nil {
		t.Fatalf("unable to decode ownership voucher to bytes: %v", err)
	}
	got, err := VerifyAndUnmarshal(decodedOV, vendorCAPool)
	if err != nil {
		t.Errorf("VerifyAndUnmarshal err = %v, want nil", err)
	}
	if gotPDC, wantPDC := got.OV.PinnedDomainCert, pdcPub; !bytes.Equal(gotPDC, wantPDC) {
		t.Errorf("got PDC = %v, want %v", gotPDC, wantPDC)
	}
	if gotSerial := got.OV.SerialNumber; gotSerial != wantSerial {
		t.Errorf("got serial = %v, want %v", gotSerial, wantSerial)
	}
}
