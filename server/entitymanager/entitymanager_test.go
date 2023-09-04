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

package entitymanager

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/openconfig/bootz/proto/bootz"
	"github.com/openconfig/bootz/server/service"
	"google.golang.org/protobuf/proto"
)

func TestFetchOwnershipVoucher(t *testing.T) {
	tests := []struct {
		desc    string
		serial  string
		want    string
		wantErr bool
	}{{
		desc:    "Missing OV",
		serial:  "123B",
		wantErr: true,
	}, {
		desc:    "Found OV",
		serial:  "123A",
		want:    "test_ov",
		wantErr: false,
	}}

	artifacts := &service.SecurityArtifacts{
		OV: service.OVList{"123A": "test_ov"},
	}
	em := New(artifacts)

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			got, err := em.FetchOwnershipVoucher(test.serial)
			if (err != nil) != test.wantErr {
				t.Fatalf("FetchOwnershipVoucher(%v) err = %v, want %v", test.serial, err, test.wantErr)
			}
			if !cmp.Equal(got, test.want) {
				t.Errorf("FetchOwnershipVoucher(%v) got %v, want %v", test.serial, got, test.want)
			}
		})
	}
}

func TestResolveChassis(t *testing.T) {
	tests := []struct {
		desc    string
		input   *service.EntityLookup
		want    *service.ChassisEntity
		wantErr bool
	}{{
		desc: "Default device",
		input: &service.EntityLookup{
			SerialNumber: "123",
			Manufacturer: "Cisco",
		},
		want: &service.ChassisEntity{
			BootMode: bootz.BootMode_BOOT_MODE_SECURE,
		},
	}, {
		desc: "Chassis Not Found",
		input: &service.EntityLookup{
			SerialNumber: "456",
			Manufacturer: "Cisco",
		},
		want:    nil,
		wantErr: true,
	},
	}

	em := New(nil).AddChassis(bootz.BootMode_BOOT_MODE_SECURE, "Cisco", "123")

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			got, err := em.ResolveChassis(test.input)
			if (err != nil) != test.wantErr {
				t.Fatalf("ResolveChassis(%v) err = %v, want %v", test.input, err, test.wantErr)
			}
			if !cmp.Equal(got, test.want) {
				t.Errorf("ResolveChassis(%v) got %v, want %v", test.input, got, test.want)
			}
		})
	}
}

func TestSign(t *testing.T) {
	tests := []struct {
		desc    string
		serial  string
		resp    *bootz.GetBootstrapDataResponse
		wantOV  string
		wantOC  string
		wantErr bool
	}{{
		desc:   "Success",
		serial: "123A",
		resp: &bootz.GetBootstrapDataResponse{
			SignedResponse: &bootz.BootstrapDataSigned{
				Responses: []*bootz.BootstrapDataResponse{
					{SerialNum: "123A"},
				},
			},
		},
		wantOV:  "test_ov",
		wantOC:  "test_oc",
		wantErr: false,
	}, {
		desc:    "Empty response",
		resp:    &bootz.GetBootstrapDataResponse{},
		wantErr: true,
	},
	}

	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}
	privPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			artifacts := &service.SecurityArtifacts{
				OV: service.OVList{test.serial: test.wantOV},
				OC: &service.KeyPair{
					Cert: test.wantOC,
					Key:  string(pem.EncodeToMemory(privPEM)),
				},
			}
			em := New(artifacts)

			err := em.Sign(test.resp, test.serial)
			if err != nil {
				if test.wantErr {
					t.Skip()
				}
				t.Errorf("Sign() err = %v, want %v", err, test.wantErr)
			}
			signedResponseBytes, err := proto.Marshal(test.resp.GetSignedResponse())
			if err != nil {
				t.Fatal(err)
			}
			hashed := sha256.Sum256(signedResponseBytes)
			sigDecoded, err := base64.StdEncoding.DecodeString(test.resp.GetResponseSignature())
			if err != nil {
				t.Fatal(err)
			}
			err = rsa.VerifyPKCS1v15(&priv.PublicKey, crypto.SHA256, hashed[:], sigDecoded)
			if err != nil {
				t.Errorf("Sign() err == %v, want %v", err, test.wantErr)
			}
			if gotOV, wantOV := string(test.resp.GetOwnershipVoucher()), test.wantOV; gotOV != wantOV {
				t.Errorf("Sign() ov = %v, want %v", gotOV, wantOV)
			}
			if gotOC, wantOC := string(test.resp.GetOwnershipCertificate()), test.wantOC; gotOC != wantOC {
				t.Errorf("Sign() oc = %v, want %v", gotOC, wantOC)
			}
		})
	}
}

func TestSetStatus(t *testing.T) {
	tests := []struct {
		desc    string
		input   *bootz.ReportStatusRequest
		wantErr bool
	}{{
		desc: "No control card states",
		input: &bootz.ReportStatusRequest{
			Status:        bootz.ReportStatusRequest_BOOTSTRAP_STATUS_SUCCESS,
			StatusMessage: "Bootstrap status succeeded",
		},
		wantErr: true,
	}, {
		desc: "Control card initialized",
		input: &bootz.ReportStatusRequest{
			Status:        bootz.ReportStatusRequest_BOOTSTRAP_STATUS_SUCCESS,
			StatusMessage: "Bootstrap status succeeded",
			States: []*bootz.ControlCardState{
				{
					SerialNumber: "123A",
					Status:       *bootz.ControlCardState_CONTROL_CARD_STATUS_INITIALIZED.Enum(),
				},
			},
		},
		wantErr: false,
	}, {
		desc: "Unknown control card",
		input: &bootz.ReportStatusRequest{
			Status:        bootz.ReportStatusRequest_BOOTSTRAP_STATUS_SUCCESS,
			StatusMessage: "Bootstrap status succeeded",
			States: []*bootz.ControlCardState{
				{
					SerialNumber: "123C",
					Status:       *bootz.ControlCardState_CONTROL_CARD_STATUS_INITIALIZED.Enum(),
				},
			},
		},
		wantErr: true,
	},
	}

	em := New(nil).AddChassis(bootz.BootMode_BOOT_MODE_SECURE, "Cisco", "123").AddControlCard("123A")

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			err := em.SetStatus(test.input)
			if (err != nil) != test.wantErr {
				t.Errorf("SetStatus(%v) err = %v, want %v", test.input, err, test.wantErr)
			}
		})
	}
}

func TestGetBootstrapData(t *testing.T) {
	tests := []struct {
		desc    string
		input   *bootz.ControlCard
		want    *bootz.BootstrapDataResponse
		wantErr bool
	}{{
		desc:    "No serial number",
		input:   &bootz.ControlCard{},
		wantErr: true,
	}, {
		desc: "Control card not found",
		input: &bootz.ControlCard{
			SerialNumber: "456A",
		},
		wantErr: true,
	}, {
		desc: "Successful bootstrap",
		input: &bootz.ControlCard{
			SerialNumber: "123A",
		},
		want: &bootz.BootstrapDataResponse{
			SerialNum: "123A",
			IntendedImage: &bootz.SoftwareImage{
				Name:          "Default Image",
				Version:       "1.0",
				Url:           "https://path/to/image",
				OsImageHash:   "ABCDEF",
				HashAlgorithm: "SHA256",
			},
			BootPasswordHash: "ABCD123",
			ServerTrustCert:  "FakeTLSCert",
			BootConfig: &bootz.BootConfig{
				VendorConfig: []byte("Vendor Config"),
				OcConfig:     []byte("OC Config"),
			},
			Credentials: &bootz.Credentials{},
		},
		wantErr: false,
	},
	}

	em := New(nil).AddChassis(bootz.BootMode_BOOT_MODE_SECURE, "Cisco", "123").AddControlCard("123A")

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			got, err := em.GetBootstrapData(test.input)
			if (err != nil) != test.wantErr {
				t.Errorf("GetBootstrapData(%v) err = %v, want %v", test.input, err, test.wantErr)
			}
			if !proto.Equal(got, test.want) {
				t.Errorf("GetBootstrapData(%v) got %v, want %v", test.input, got, test.want)
			}
		})
	}
}
