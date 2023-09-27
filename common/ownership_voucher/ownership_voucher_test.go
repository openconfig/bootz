package ownershipvoucher

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"

	_ "embed"
)

var (
	wantSerial = "123A"
	//go:embed ov_123A.txt
	testOV string
	//go:embed pdc_pub.pem
	pdcPub []byte
	//go:embed vendorca_pub.pem
	vendorCAPub []byte
	//go:embed vendorca_priv.pem
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

	got, err := New(wantSerial, pdcPub, pubCert, privKey)
	if err != nil {
		t.Errorf("New err = %v, want nil", err)
	}

	vendorCAPool := x509.NewCertPool()
	if !vendorCAPool.AppendCertsFromPEM(vendorCAPub) {
		t.Fatalf("unable to add vendor root CA to pool")
	}

	_, err = VerifyAndUmarshal(got, vendorCAPool)
	if err != nil {
		t.Errorf("VerifyAndUnmarshal err = %v, want nil", err)
	}
}

// Tests VerifyAndUnmarshal using a known good OV.
func TestVerifyAndUmarshal(t *testing.T) {
	vendorCAPool := x509.NewCertPool()
	if !vendorCAPool.AppendCertsFromPEM(vendorCAPub) {
		t.Fatalf("unable to add vendor root CA to pool")
	}

	decodedOV, err := base64.StdEncoding.DecodeString(testOV)
	if err != nil {
		t.Fatalf("unable to decode ownership voucher to bytes: %v", err)
	}
	got, err := VerifyAndUmarshal(decodedOV, vendorCAPool)
	if err != nil {
		t.Errorf("VerifyAndUnmarshal err = %v, want nil", err)
	}
	if gotPDC, wantPDC := got.OV.PinnedDomainCert, RemovePemHeaders(string(pdcPub)); gotPDC != wantPDC {
		t.Errorf("got PDC = %v, want %v", gotPDC, wantPDC)
	}
	if gotSerial := got.OV.SerialNumber; gotSerial != wantSerial {
		t.Errorf("got serial = %v, want %v", gotSerial, wantSerial)
	}
}
