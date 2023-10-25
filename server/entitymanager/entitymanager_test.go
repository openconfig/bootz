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
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/h-fam/errdiff"
	"github.com/openconfig/bootz/common/signature"
	"github.com/openconfig/bootz/server/service"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	bpb "github.com/openconfig/bootz/proto/bootz"
	epb "github.com/openconfig/bootz/server/entitymanager/proto/entity"
	apb "github.com/openconfig/gnsi/authz"
)

// MustMarshalBootstrapDataSigned is a helper function that marshals a BootstrapDataSigned message.
func MustMarshalBootstrapDataSigned(t *testing.T, b *bpb.BootstrapDataSigned) []byte {
	t.Helper()
	bytes, err := proto.Marshal(b)
	if err != nil {
		t.Fatalf("MustMarshalBootstrapDataSigned(t, m) = %v; want %v", err, nil)
	}
	return bytes
}

func TestNew(t *testing.T) {
	ov1 := readTextFromFile(t, "../../testdata/ov_123A.txt")
	ov2 := readTextFromFile(t, "../../testdata/ov_123B.txt")
	chassis := epb.Chassis{
		Name:                   "test",
		SerialNumber:           "123",
		Manufacturer:           "Cisco",
		BootloaderPasswordHash: "ABCD123",
		BootMode:               bpb.BootMode_BOOT_MODE_INSECURE,
		Config: &epb.Config{
			BootConfig: &epb.BootConfig{},
			GnsiConfig: &epb.GNSIConfig{},
		},
		SoftwareImage: &bpb.SoftwareImage{
			Name:          "Default Image",
			Version:       "1.0",
			Url:           "https://path/to/image",
			OsImageHash:   "e9c0f8b575cbfcb42ab3b78ecc87efa3b011d9a5d10b09fa4e96f240bf6a82f5",
			HashAlgorithm: "SHA256",
		},
		ControllerCards: []*epb.ControlCard{
			{
				SerialNumber:     "123A",
				PartNumber:       "123A",
				OwnershipVoucher: ov1,
				DhcpConfig:       &epb.DHCPConfig{},
			},
			{
				SerialNumber:     "123B",
				PartNumber:       "123B",
				OwnershipVoucher: ov2,
				DhcpConfig:       &epb.DHCPConfig{},
			},
		},
		DhcpConfig: &epb.DHCPConfig{},
	}
	tests := []struct {
		desc        string
		chassisConf string
		inventory   map[service.EntityLookup]*epb.Chassis
		defaults    *epb.Options
		wantErr     string
	}{
		{
			desc:        "Successful new with file",
			chassisConf: "../../testdata/inventory.prototxt",
			inventory: map[service.EntityLookup]*epb.Chassis{
				{
					ChassisSerialNumber: chassis.SerialNumber,
					Manufacturer:        chassis.Manufacturer,
					ModularChassis:      true,
				}: &chassis,
			},
			defaults: &epb.Options{
				Bootzserver: "bootzip:....",
				ArtifactDir: "../../testdata/",
				GnsiGlobalConfig: &epb.GNSIConfig{
					AuthzUploadFile: "../../testdata/authz.prototext",
				},
			},
		},
		{
			desc:        "Unsuccessful with wrong security artifacts",
			chassisConf: "../../testdata/inv_with_wrong_sec.prototxt",
			wantErr:     "security artifacts",
		},
		{
			desc:        "Unsuccessful new with wrong file",
			chassisConf: "../../testdata/wrong_inventory.prototxt",
			inventory:   map[service.EntityLookup]*epb.Chassis{},
			wantErr:     "proto:",
		},
		{
			desc:        "Unsuccessful new with wrong file path",
			chassisConf: "not/valid/path",
			inventory:   map[service.EntityLookup]*epb.Chassis{},
			wantErr:     "no such file or directory",
		},
		{
			desc:        "Successful new with empty file path",
			chassisConf: "",
			inventory:   map[service.EntityLookup]*epb.Chassis{},
			defaults:    &epb.Options{GnsiGlobalConfig: &epb.GNSIConfig{}},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			inv, err := New(test.chassisConf)
			if err == nil {
				opts := []cmp.Option{
					protocmp.Transform(),
					protocmp.IgnoreMessages(&epb.Chassis{}, &epb.Options{}, &bpb.SoftwareImage{}, &epb.DHCPConfig{}, &epb.GNSIConfig{}, &epb.BootConfig{}, &epb.Config{}, &epb.BootConfig{}, &epb.ControlCard{}),
					cmpopts.IgnoreUnexported(service.EntityLookup{}),
				}
				if !cmp.Equal(inv.chassisInventory, test.inventory, opts...) {
					t.Errorf("Inventory list is not as expected, Diff: %s", cmp.Diff(inv.chassisInventory, test.inventory, opts...))
				}
				if !cmp.Equal(inv.defaults, test.defaults, opts...) {
					t.Errorf("Inventory list is not as expected, Diff: %s", cmp.Diff(inv.defaults, test.defaults, opts...))
				}
			}
			if s := errdiff.Substring(err, test.wantErr); s != "" {
				t.Errorf("Expected error %s, but got error %v", test.wantErr, err)
			}
		})
	}

}

func TestFetchOwnershipVoucher(t *testing.T) {
	ov1 := readTextFromFile(t, "../../testdata/ov_123A.txt")
	ov2 := readTextFromFile(t, "../../testdata/ov_123B.txt")
	chassis := epb.Chassis{
		Name:                   "test",
		SerialNumber:           "123",
		Manufacturer:           "Cisco",
		BootloaderPasswordHash: "ABCD123",
		BootMode:               bpb.BootMode_BOOT_MODE_INSECURE,
		Config: &epb.Config{
			BootConfig: &epb.BootConfig{},
			GnsiConfig: &epb.GNSIConfig{},
		},
		SoftwareImage: &bpb.SoftwareImage{
			Name:          "Default Image",
			Version:       "1.0",
			Url:           "https://path/to/image",
			OsImageHash:   "ABCDEF",
			HashAlgorithm: "SHA256",
		},
		ControllerCards: []*epb.ControlCard{
			{
				SerialNumber:     "123A",
				PartNumber:       "123A",
				OwnershipVoucher: ov1,
				DhcpConfig:       &epb.DHCPConfig{},
			},
			{
				SerialNumber:     "123B",
				PartNumber:       "123B",
				OwnershipVoucher: ov2,
				DhcpConfig:       &epb.DHCPConfig{},
			},
		},
	}
	tests := []struct {
		desc    string
		serial  string
		want    string
		wantErr bool
	}{{
		desc:    "Missing OV",
		serial:  "MissingSerial",
		wantErr: true,
	}, {
		desc:    "Found OV",
		serial:  "123A",
		want:    ov1,
		wantErr: false,
	}}

	em, _ := New("")

	em.chassisInventory[service.EntityLookup{
		ModularChassis:      true,
		Manufacturer:        "Cisco",
		ChassisSerialNumber: "123",
	}] = &chassis

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			got, err := em.fetchOwnershipVoucher(&service.EntityLookup{ModularChassis: true, Manufacturer: "Cisco", ChassisSerialNumber: "123"}, test.serial)
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
		desc: "Fixed form factor device",
		input: &service.EntityLookup{
			ChassisSerialNumber: "123",
			Manufacturer:        "Cisco",
			ModularChassis:      false,
		},
		want: &service.ChassisEntity{
			BootMode: bpb.BootMode_BOOT_MODE_SECURE,
		},
	}, {
		desc: "Chassis Not Found",
		input: &service.EntityLookup{
			ChassisSerialNumber: "456",
			Manufacturer:        "Cisco",
		},
		want:    nil,
		wantErr: true,
	}, {
		desc: "Modular chassis",
		input: &service.EntityLookup{
			ControlCardSerialNumber: "789A",
			Manufacturer:            "Cisco",
			ModularChassis:          true,
		},
		want: &service.ChassisEntity{
			BootMode: bpb.BootMode_BOOT_MODE_SECURE,
		},
		wantErr: false,
	},
	}
	em, _ := New("")
	em.AddChassis(bpb.BootMode_BOOT_MODE_SECURE, "Cisco", "123")
	em.AddChassis(bpb.BootMode_BOOT_MODE_SECURE, "Cisco", "789")
	_, err := em.AttachControlCard("789", "Cisco", &epb.ControlCard{
		SerialNumber: "789A",
	})
	if err != nil {
		t.Fatalf("unable to attach control card to chassis: %v", err)
	}

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
	ov1 := readTextFromFile(t, "../../testdata/ov_123A.txt")
	tests := []struct {
		desc    string
		lookup  service.EntityLookup
		serial  string
		resp    *bpb.GetBootstrapDataResponse
		wantOV  string
		wantOC  bool
		wantErr bool
	}{{
		desc: "Success",
		lookup: service.EntityLookup{
			Manufacturer:        "Cisco",
			ChassisSerialNumber: "123",
			ModularChassis:      true,
		},
		serial: "123A",
		resp: &bpb.GetBootstrapDataResponse{
			SerializedBootstrapData: MustMarshalBootstrapDataSigned(t, &bpb.BootstrapDataSigned{
				Responses: []*bpb.BootstrapDataResponse{
					{SerialNum: "123A"},
				},
			}),
		},
		wantOV:  ov1,
		wantOC:  true,
		wantErr: false,
	}, {
		desc:    "Empty response",
		resp:    &bpb.GetBootstrapDataResponse{},
		wantErr: true,
	},
	}

	em, _ := New("../../testdata/inventory.prototxt")
	artifacts, err := parseSecurityArtifacts(em.defaults.GetArtifactDir())
	if err != nil {
		t.Fatalf("Could not load security artifacts: %v", err)
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {

			err = em.Sign(test.resp, &test.lookup, test.serial)
			if err != nil {
				if test.wantErr {
					t.Skip()
				}
				t.Errorf("Sign() err = %v, want %v", err, test.wantErr)
			}

			block, _ := pem.Decode([]byte(artifacts.OC.Cert))
			if block == nil {
				t.Fatal("unable to decode OC public key")
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal("unable to parse OC public key")
			}

			err = signature.Verify(cert, test.resp.GetSerializedBootstrapData(), test.resp.GetResponseSignature())
			if err != nil {
				t.Errorf("Verify() err == %v, want %v", err, test.wantErr)
			}
			wantOVByte, err := base64.StdEncoding.DecodeString(test.wantOV)
			if err != nil {
				t.Fatalf("Error during Decoding base64 is not expected, %v", err)
			}
			if string(test.resp.GetOwnershipVoucher()) != string(wantOVByte) {
				t.Errorf("Sign() ov = %v, want %v", test.resp.GetOwnershipVoucher(), test.wantOV)
			}
			if test.wantOC {
				if gotOC, wantOC := string(test.resp.GetOwnershipCertificate()), artifacts.OC.Cert; gotOC != wantOC {
					t.Errorf("Sign() oc = %v, want %v", gotOC, wantOC)
				}
			}
		})
	}
}

func TestSetStatus(t *testing.T) {
	tests := []struct {
		desc    string
		input   *bpb.ReportStatusRequest
		wantErr bool
	}{{
		desc: "No control card states",
		input: &bpb.ReportStatusRequest{
			Status:        bpb.ReportStatusRequest_BOOTSTRAP_STATUS_SUCCESS,
			StatusMessage: "Bootstrap status succeeded",
		},
		wantErr: true,
	}, {
		desc: "Control card initialized",
		input: &bpb.ReportStatusRequest{
			Status:        bpb.ReportStatusRequest_BOOTSTRAP_STATUS_SUCCESS,
			StatusMessage: "Bootstrap status succeeded",
			States: []*bpb.ControlCardState{
				{
					SerialNumber: "123A",
					Status:       *bpb.ControlCardState_CONTROL_CARD_STATUS_INITIALIZED.Enum(),
				},
			},
		},
		wantErr: false,
	}, {
		desc: "Unknown control card",
		input: &bpb.ReportStatusRequest{
			Status:        bpb.ReportStatusRequest_BOOTSTRAP_STATUS_SUCCESS,
			StatusMessage: "Bootstrap status succeeded",
			States: []*bpb.ControlCardState{
				{
					SerialNumber: "123C",
					Status:       *bpb.ControlCardState_CONTROL_CARD_STATUS_INITIALIZED.Enum(),
				},
			},
		},
		wantErr: true,
	},
	}
	em, _ := New("")
	em.AddChassis(bpb.BootMode_BOOT_MODE_SECURE, "Cisco", "123").AddControlCard("123A")

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
	ov1 := readTextFromFile(t, "../../testdata/ov_123A.txt")
	ov2 := readTextFromFile(t, "../../testdata/ov_123B.txt")
	chassis := epb.Chassis{
		Name:                   "test",
		SerialNumber:           "123",
		Manufacturer:           "Cisco",
		BootloaderPasswordHash: "ABCD123",
		BootMode:               bpb.BootMode_BOOT_MODE_INSECURE,
		Config: &epb.Config{
			BootConfig: &epb.BootConfig{},
			GnsiConfig: &epb.GNSIConfig{
				AuthzUploadFile: "../../testdata/authz.prototext",
			},
		},
		SoftwareImage: &bpb.SoftwareImage{
			Name:          "Default Image",
			Version:       "1.0",
			Url:           "https://path/to/image",
			OsImageHash:   "ABCDEF",
			HashAlgorithm: "SHA256",
		},
		ControllerCards: []*epb.ControlCard{
			{
				SerialNumber:     "123A",
				PartNumber:       "123A",
				OwnershipVoucher: ov1,
				DhcpConfig:       &epb.DHCPConfig{},
			},
			{
				SerialNumber:     "123B",
				PartNumber:       "123B",
				OwnershipVoucher: ov2,
				DhcpConfig:       &epb.DHCPConfig{},
			},
		},
	}
	tests := []struct {
		desc                string
		input               *bpb.ControlCard
		chassisSerial       string
		chassisManufacturer string
		want                *bpb.BootstrapDataResponse
		wantErr             bool
	}{{
		desc:                "No controller card, but valid chassis (success)",
		input:               nil,
		chassisSerial:       "123",
		chassisManufacturer: "Cisco",
		want: &bpb.BootstrapDataResponse{
			SerialNum: "123",
			IntendedImage: &bpb.SoftwareImage{
				Name:          "Default Image",
				Version:       "1.0",
				Url:           "https://path/to/image",
				OsImageHash:   "ABCDEF",
				HashAlgorithm: "SHA256",
			},
			BootPasswordHash: "ABCD123",
			ServerTrustCert:  "FakeTLSCert",
			BootConfig: &bpb.BootConfig{
				VendorConfig: []byte(""),
				OcConfig:     []byte(""),
			},
			Credentials: &bpb.Credentials{},
			Authz: &apb.UploadRequest{
				Version:   "v0.1694813669807611349",
				CreatedOn: 1694813669807,
				Policy:    "{\"name\":\"default\",\"request\":{\"paths\":[\"*\"]},\"source\":{\"principals\":[\"cafyauto\"]}}",
			},
		},
		wantErr: false,
	}, {
		desc:    "No controller card and no chassis serial (fail)",
		input:   nil,
		wantErr: true,
	}, {
		desc: "Control card not found",
		input: &bpb.ControlCard{
			SerialNumber: "456A",
		},
		wantErr: true,
	}, {
		desc: "Successful bootstrap, valid chassis serial and controller card",
		input: &bpb.ControlCard{
			SerialNumber: "123A",
			PartNumber:   "123A",
		},
		chassisSerial:       "123",
		chassisManufacturer: "Cisco",
		want: &bpb.BootstrapDataResponse{
			SerialNum: "123A",
			IntendedImage: &bpb.SoftwareImage{
				Name:          "Default Image",
				Version:       "1.0",
				Url:           "https://path/to/image",
				OsImageHash:   "ABCDEF",
				HashAlgorithm: "SHA256",
			},
			BootPasswordHash: "ABCD123",
			ServerTrustCert:  "FakeTLSCert",
			BootConfig: &bpb.BootConfig{
				VendorConfig: []byte(""),
				OcConfig:     []byte(""),
			},
			Credentials: &bpb.Credentials{},
			Authz: &apb.UploadRequest{
				Version:   "v0.1694813669807611349",
				CreatedOn: 1694813669807,
				Policy:    "{\"name\":\"default\",\"request\":{\"paths\":[\"*\"]},\"source\":{\"principals\":[\"cafyauto\"]}}",
			},
		},
		wantErr: false,
	}, {
		desc: "Successful bootstrap, no chassis serial but valid controller card",
		input: &bpb.ControlCard{
			SerialNumber: "123A",
			PartNumber:   "123A",
		},
		chassisSerial:       "",
		chassisManufacturer: "Cisco",
		want: &bpb.BootstrapDataResponse{
			SerialNum: "123A",
			IntendedImage: &bpb.SoftwareImage{
				Name:          "Default Image",
				Version:       "1.0",
				Url:           "https://path/to/image",
				OsImageHash:   "ABCDEF",
				HashAlgorithm: "SHA256",
			},
			BootPasswordHash: "ABCD123",
			ServerTrustCert:  "FakeTLSCert",
			BootConfig: &bpb.BootConfig{
				VendorConfig: []byte(""),
				OcConfig:     []byte(""),
			},
			Credentials: &bpb.Credentials{},
			Authz: &apb.UploadRequest{
				Version:   "v0.1694813669807611349",
				CreatedOn: 1694813669807,
				Policy:    "{\"name\":\"default\",\"request\":{\"paths\":[\"*\"]},\"source\":{\"principals\":[\"cafyauto\"]}}",
			},
		},
		wantErr: false,
	}, {
		desc: "Unsuccessful bootstrap, no chassis serial, valid controller card, not matching manufacturer",
		input: &bpb.ControlCard{
			SerialNumber: "123A",
			PartNumber:   "123A",
		},
		chassisSerial:       "",
		chassisManufacturer: "",
		wantErr:             true,
	},
	}

	em, _ := New("")
	em.chassisInventory[service.EntityLookup{Manufacturer: "Cisco", ChassisSerialNumber: "123"}] = &chassis

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			got, err := em.GetBootstrapData(&service.EntityLookup{ChassisSerialNumber: test.chassisSerial, Manufacturer: test.chassisManufacturer}, test.input)
			if (err != nil) != test.wantErr {
				t.Errorf("GetBootstrapData(%v) err = %v, want %v", test.input, err, test.wantErr)
			}
			if !proto.Equal(got, test.want) {
				t.Errorf("GetBootstrapData(%v) \n got: %v, \n want: %v", test.input, got, test.want)
			}
		})
	}
}

func readTextFromFile(t *testing.T, file string) string {
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("Could not read file %s: v", file)
	}
	return string(data)
}

func TestLoadConfig(t *testing.T) {
	vendorCliConfig := readTextFromFile(t, "../../testdata/cisco.cfg")
	tests := []struct {
		desc             string
		bootConfig       *epb.BootConfig
		wantBootConfig   *bpb.BootConfig
		wantVendorConfig []byte
		wantErr          string
	}{
		{
			desc: "Successful OC/vendor config",
			bootConfig: &epb.BootConfig{
				VendorConfigFile: "../../testdata/cisco.cfg",
				OcConfigFile:     "../../testdata/oc_config.json",
			},
			wantBootConfig: &bpb.BootConfig{
				VendorConfig: []byte(vendorCliConfig),
			},
			wantVendorConfig: []byte{},
			wantErr:          "",
		},
		{
			desc: "Unsuccessful OC config",
			bootConfig: &epb.BootConfig{
				VendorConfigFile: "../../testdata/cisco.cfg",
				OcConfigFile:     "../../testdata/wrong_oc_config.prototext",
			},
			wantBootConfig: &bpb.BootConfig{
				VendorConfig: []byte(vendorCliConfig),
			},
			wantVendorConfig: []byte{},
			wantErr:          "proto",
		},
		{
			desc: "Unsuccessful OC config due to file path",
			bootConfig: &epb.BootConfig{
				VendorConfigFile: "../../testdata/cisco.cfg",
				OcConfigFile:     "../../wrong_path.prototext",
			},
			wantBootConfig: &bpb.BootConfig{
				VendorConfig: []byte(vendorCliConfig),
			},
			wantVendorConfig: []byte{},
			wantErr:          "file",
		},
		{
			desc: "Unsuccessful vendor config due to path",
			bootConfig: &epb.BootConfig{
				VendorConfigFile: "../../wrong/path",
				OcConfigFile:     "../../testdata/oc_config.prototext",
			},
			wantBootConfig: &bpb.BootConfig{
				VendorConfig: []byte(vendorCliConfig),
			},
			wantVendorConfig: []byte{},
			wantErr:          "file",
		},
	}
	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			gotBootConfig, err := populateBootConfig(test.bootConfig)
			if err == nil {
				if diff := cmp.Diff(test.wantBootConfig.GetVendorConfig(), gotBootConfig.GetVendorConfig()); diff != "" {
					t.Fatalf("wanted vendor config differs from the got config %s", diff)
				}
			}
			if errdiff.Substring(err, test.wantErr) != "" {
				t.Errorf("Unexocted error, %s", errdiff.Text(err, test.wantErr))
			}

		})
	}
}

func TestGetDevice(t *testing.T) {
	tests := []struct {
		name             string
		chassisInventory *epb.Entities
		wantErr          string
	}{
		{
			name: "Successfully GetDevice",
			chassisInventory: &epb.Entities{
				Chassis: []*epb.Chassis{
					{
						SerialNumber: "1234",
						Manufacturer: "cisco",
					},
				},
			},
			wantErr: "",
		},
		{
			name: "Unsuccessfully GetDevice",
			chassisInventory: &epb.Entities{
				Chassis: []*epb.Chassis{
					{
						PartNumber:   "5678",
						Manufacturer: "sysco",
					},
				},
			},
			wantErr: "Could not find chassis with serial#: 1234 and manufacturer: cisco",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configsMap := make(map[service.EntityLookup]*epb.Chassis)
			for _, chassis := range tt.chassisInventory.Chassis {
				configsMap[service.EntityLookup{ChassisSerialNumber: chassis.SerialNumber, Manufacturer: chassis.Manufacturer}] = chassis
			}

			em := InMemoryEntityManager{
				chassisInventory: configsMap,
			}

			lookup := service.EntityLookup{ChassisSerialNumber: "1234", Manufacturer: "cisco"}

			want, exists := em.chassisInventory[lookup]

			received, err := em.GetDevice(&lookup)

			if s := errdiff.Check(err, tt.wantErr); s != "" {
				t.Errorf("Expected error %s, but got error %v", tt.wantErr, err)
			} else if exists && !(proto.Equal(want, received)) {
				t.Errorf("Result of GetDevice does not match expected\nwant:\n\t%s\nactual:\n\t%s", want, received)
			}
		})
	}
}

func TestGetAll(t *testing.T) {
	tests := []struct {
		chassisInventory *epb.Entities
		name             string
	}{
		{
			name: "Successful GetAll",
			chassisInventory: &epb.Entities{
				Chassis: []*epb.Chassis{
					{
						SerialNumber: "1234",
						Manufacturer: "cisco",
					},
					{
						SerialNumber: "5678",
						Manufacturer: "cisco",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configsMap := make(map[service.EntityLookup]*epb.Chassis)
			for _, chassis := range tt.chassisInventory.Chassis {
				configsMap[service.EntityLookup{ChassisSerialNumber: chassis.SerialNumber, Manufacturer: chassis.Manufacturer}] = chassis
			}

			em := InMemoryEntityManager{
				chassisInventory: configsMap,
			}
			received := em.GetAll()

			if !(cmp.Equal(configsMap, received, protocmp.Transform())) {
				t.Errorf("Result of GetDevice does not match expected\nwant:\n\t%v\nactual:\n\t%v", configsMap, received)
			}
		})
	}
}

func TestReplaceDevice(t *testing.T) {
	tests := []struct {
		chassisInventory     *epb.Entities
		wantChassisInventory *epb.Entities
		name                 string
		wantErr              string
	}{
		{
			name: "Successfully ReplaceDevice",
			chassisInventory: &epb.Entities{
				Chassis: []*epb.Chassis{
					{
						SerialNumber: "1234",
						Manufacturer: "cisco",
					},
				},
			},
			wantChassisInventory: &epb.Entities{
				Chassis: []*epb.Chassis{
					{
						SerialNumber: "5678",
						Manufacturer: "cisco",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configsMap := make(map[service.EntityLookup]*epb.Chassis)
			for _, chassis := range tt.chassisInventory.Chassis {
				configsMap[service.EntityLookup{ChassisSerialNumber: chassis.SerialNumber, Manufacturer: chassis.Manufacturer}] = chassis
			}

			want := make(map[service.EntityLookup]*epb.Chassis)
			for _, chassis := range tt.wantChassisInventory.Chassis {
				want[service.EntityLookup{ChassisSerialNumber: chassis.SerialNumber, Manufacturer: chassis.Manufacturer}] = chassis
			}

			em := InMemoryEntityManager{
				chassisInventory: configsMap,
			}

			newObj := &epb.Chassis{
				SerialNumber: "5678",
				Manufacturer: "cisco",
			}

			err := em.ReplaceDevice(&service.EntityLookup{ChassisSerialNumber: "1234", Manufacturer: "cisco"}, newObj)

			received := em.chassisInventory

			// todo: This test will require error checking after ValidateConfig is implemented.

			if s := errdiff.Check(err, tt.wantErr); s != "" {
				t.Errorf("Expected error %s, but got error %v", tt.wantErr, err)
			} else if !(cmp.Equal(want, received, protocmp.Transform())) {
				t.Errorf("Result of ReplaceDevice does not match expected\nwant:\n\t%v\nactual:\n\t%v", want, received)
			}
		})
	}
}

func TestDeleteDevice(t *testing.T) {
	tests := []struct {
		chassisInventory     *epb.Entities
		wantChassisInventory *epb.Entities
		name                 string
	}{
		{
			name: "Successfully DeleteDevice",
			chassisInventory: &epb.Entities{
				Chassis: []*epb.Chassis{
					{
						SerialNumber: "1234",
						Manufacturer: "cisco",
					},
				},
			},
			wantChassisInventory: &epb.Entities{},
		},
		{
			name: "DeleteDevice nonexistent",
			chassisInventory: &epb.Entities{
				Chassis: []*epb.Chassis{
					{
						SerialNumber: "5678",
						Manufacturer: "cisco",
					},
				},
			},
			wantChassisInventory: &epb.Entities{
				Chassis: []*epb.Chassis{
					{
						SerialNumber: "5678",
						Manufacturer: "cisco",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configsMap := make(map[service.EntityLookup]*epb.Chassis)
			for _, chassis := range tt.chassisInventory.Chassis {
				configsMap[service.EntityLookup{ChassisSerialNumber: chassis.SerialNumber, Manufacturer: chassis.Manufacturer}] = chassis
			}

			want := make(map[service.EntityLookup]*epb.Chassis)
			for _, chassis := range tt.wantChassisInventory.Chassis {
				want[service.EntityLookup{ChassisSerialNumber: chassis.SerialNumber, Manufacturer: chassis.Manufacturer}] = chassis
			}

			em := InMemoryEntityManager{
				chassisInventory: configsMap,
			}

			em.DeleteDevice(&service.EntityLookup{ChassisSerialNumber: "1234", Manufacturer: "cisco"})

			if !(cmp.Equal(want, em.chassisInventory, protocmp.Transform())) {
				t.Errorf("Result of DeleteDevice does not match expected\nwant:\n\t%v\nactual:\n\t%v", want, em.chassisInventory)
			}
		})
	}
}
