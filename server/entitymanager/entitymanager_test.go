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
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/h-fam/errdiff"
	ownercertificate "github.com/openconfig/bootz/common/owner_certificate"
	"github.com/openconfig/bootz/common/signature"
	"github.com/openconfig/bootz/server/service"
	artifacts "github.com/openconfig/bootz/testdata"
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
	a, err := artifacts.GenerateSecurityArtifacts([]string{"123A", "123B"}, "Google", "Cisco")
	if err != nil {
		t.Fatalf("unable to generate server artifacts: %v", err)
	}
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
			OsImageHash:   "e9:c0:f8:b5:75:cb:fc:b4:2a:b3:b7:8e:cc:87:ef:a3:b0:11:d9:a5:d1:0b:09:fa:4e:96:f2:40:bf:6a:82:f5",
			HashAlgorithm: "ietf-sztp-conveyed-info:sha-256",
		},
		ControllerCards: []*epb.ControlCard{
			{
				SerialNumber: "123A",
				PartNumber:   "123A",
				DhcpConfig:   &epb.DHCPConfig{},
			},
			{
				SerialNumber: "123B",
				PartNumber:   "123B",
				DhcpConfig:   &epb.DHCPConfig{},
			},
		},
		DhcpConfig: &epb.DHCPConfig{},
	}
	tests := []struct {
		desc        string
		chassisConf string
		inventory   []*epb.Chassis
		defaults    *epb.Options
		wantErr     string
	}{
		{
			desc:        "Successful new with file",
			chassisConf: "../../testdata/inventory.prototxt",
			inventory:   []*epb.Chassis{&chassis},
			defaults: &epb.Options{
				Bootzserver: "bootzip:....",
				ArtifactDir: "../../testdata/",
				GnsiGlobalConfig: &epb.GNSIConfig{
					AuthzUploadFile: "../../testdata/authz.prototext",
				},
			},
		},
		{
			desc:        "Unsuccessful new with wrong file",
			chassisConf: "../../testdata/wrong_inventory.prototxt",
			inventory:   []*epb.Chassis{},
			wantErr:     "proto:",
		},
		{
			desc:        "Unsuccessful new with wrong file path",
			chassisConf: "not/valid/path",
			inventory:   []*epb.Chassis{},
			wantErr:     "no such file or directory",
		},
		{
			desc:        "Successful new with empty file path",
			chassisConf: "",
			inventory:   nil,
			defaults:    &epb.Options{GnsiGlobalConfig: &epb.GNSIConfig{}},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			inv, err := New(test.chassisConf, a)
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
	a, err := artifacts.GenerateSecurityArtifacts([]string{"123A", "123B"}, "Google", "Cisco")
	if err != nil {
		t.Fatalf("unable to generate server artifacts: %v", err)
	}
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
				SerialNumber: "123A",
				PartNumber:   "123A",
				DhcpConfig:   &epb.DHCPConfig{},
			},
			{
				SerialNumber: "123B",
				PartNumber:   "123B",
				DhcpConfig:   &epb.DHCPConfig{},
			},
		},
	}
	tests := []struct {
		desc    string
		serial  string
		want    []byte
		wantErr bool
	}{{
		desc:    "Missing OV",
		serial:  "MissingSerial",
		wantErr: true,
	}, {
		desc:    "Found OV",
		serial:  "123A",
		want:    a.OV["123A"],
		wantErr: false,
	}}

	em, _ := New("", a)
	em.chassisInventory = []*epb.Chassis{&chassis}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			got, err := em.fetchOwnershipVoucher(test.serial)
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
	ctx := context.Background()
	tests := []struct {
		desc    string
		input   *service.EntityLookup
		want    *service.Chassis
		wantErr bool
	}{{
		desc: "Default device",
		input: &service.EntityLookup{
			SerialNumber: "123",
			Manufacturer: "Cisco",
		},
		want: &service.Chassis{
			Hostname:     "test",
			Manufacturer: "Cisco",
			Realm:        "prod",
			Serial:       "123",
			BootMode:     bpb.BootMode_BOOT_MODE_INSECURE,
			SoftwareImage: &bpb.SoftwareImage{
				HashAlgorithm: "ietf-sztp-conveyed-info:sha-256",
				Name:          "Default Image",
				OsImageHash:   "e9:c0:f8:b5:75:cb:fc:b4:2a:b3:b7:8e:cc:87:ef:a3:b0:11:d9:a5:d1:0b:09:fa:4e:96:f2:40:bf:6a:82:f5",
				Url:           "https://path/to/image",
				Version:       "1.0",
			},
			ControlCards: []*service.ControlCard{
				{
					Manufacturer: "Cisco",
					PartNumber:   "123A",
					Serial:       "123A",
				},
				{
					Manufacturer: "Cisco",
					PartNumber:   "123B",
					Serial:       "123B",
				},
			},
			BootConfig: &bpb.BootConfig{},
			Authz: &apb.UploadRequest{
				CreatedOn: 1694813669807,
				Policy:    `{"name":"default","request":{"paths":["*"]},"source":{"principals":["cafyauto"]}}`,
				Version:   "v0.1694813669807611349",
			},
			BootloaderPasswordHash: "ABCD123",
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
	em, err := New("../../testdata/inventory.prototxt", nil)
	if err != nil {
		t.Fatalf("failed to create entity manager: %v", err)
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			got, err := em.ResolveChassis(ctx, test.input, "")
			if (err != nil) != test.wantErr {
				t.Fatalf("ResolveChassis(%v) err = %v, want %v", test.input, err, test.wantErr)
			}
			if diff := cmp.Diff(got, test.want, protocmp.Transform()); diff != "" {
				t.Errorf("ResolveChassis(%v) diff = %v", test.input, diff)
			}
		})
	}
}

func TestSign(t *testing.T) {
	a, err := artifacts.GenerateSecurityArtifacts([]string{"123A"}, "Google", "Cisco")
	if err != nil {
		t.Fatalf("unable to generate server artifacts: %v", err)
	}
	ctx := context.Background()
	tests := []struct {
		desc    string
		chassis service.Chassis
		serial  string
		resp    *bpb.GetBootstrapDataResponse
		wantOC  bool
		wantErr bool
	}{{
		desc: "Success",
		chassis: service.Chassis{
			Manufacturer: "Cisco",
			Serial:       "123",
			ControlCards: []*service.ControlCard{
				{
					Serial:       "123A",
					Manufacturer: "Cisco",
					PartNumber:   "123A",
				},
			},
		},
		serial: "123A",
		resp: &bpb.GetBootstrapDataResponse{
			SerializedBootstrapData: MustMarshalBootstrapDataSigned(t, &bpb.BootstrapDataSigned{
				Responses: []*bpb.BootstrapDataResponse{
					{SerialNum: "123A"},
				},
			}),
		},
		wantOC:  true,
		wantErr: false,
	}, {
		desc:    "Empty response",
		resp:    &bpb.GetBootstrapDataResponse{},
		wantErr: true,
	},
	}

	em, err := New("../../testdata/inventory.prototxt", a)
	if err != nil {
		t.Fatalf("Could not load security artifacts: %v", err)
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			err = em.Sign(ctx, test.resp, &test.chassis, test.serial)
			if err != nil {
				if test.wantErr {
					t.Skip()
				}
				t.Errorf("Sign() err = %v, want %v", err, test.wantErr)
			}

			err = signature.Verify(a.OwnerCert, test.resp.GetSerializedBootstrapData(), test.resp.GetResponseSignature())
			if err != nil {
				t.Errorf("Verify() err == %v, want %v", err, test.wantErr)
			}
			if !bytes.Equal(test.resp.GetOwnershipVoucher(), a.OV[test.serial]) {
				t.Errorf("Sign() ov = %v, want %v", test.resp.GetOwnershipVoucher(), a.OV[test.serial])
			}
			wantOC, err := ownercertificate.GenerateCMS(a.OwnerCert, a.OwnerCertPrivateKey)
			if err != nil {
				t.Fatalf("unable to generate OC CMS: %v", err)
			}
			if test.wantOC {
				if !bytes.Equal(test.resp.GetOwnershipCertificate(), wantOC) {
					t.Errorf("Sign() oc = %v, want %v", test.resp.GetOwnershipCertificate(), a.OwnerCert.Raw)
				}
			}
		})
	}
}

func TestSetStatus(t *testing.T) {
	ctx := context.Background()
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
		desc: "Known control card initialized",
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
		desc: "Unseen control card initialized",
		input: &bpb.ReportStatusRequest{
			Status:        bpb.ReportStatusRequest_BOOTSTRAP_STATUS_SUCCESS,
			StatusMessage: "Bootstrap status succeeded",
			States: []*bpb.ControlCardState{
				{
					SerialNumber: "123B",
					Status:       *bpb.ControlCardState_CONTROL_CARD_STATUS_INITIALIZED.Enum(),
				},
			},
		},
		wantErr: false,
	},
	}
	em, _ := New("", nil)
	em.AddChassis(bpb.BootMode_BOOT_MODE_SECURE, "Cisco", "123").AddControlCard("123A")

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			err := em.SetStatus(ctx, test.input)
			if (err != nil) != test.wantErr {
				t.Errorf("SetStatus(%v) err = %v, want %v", test.input, err, test.wantErr)
			}
		})
	}
}

func TestGetBootstrapData(t *testing.T) {
	a, err := artifacts.GenerateSecurityArtifacts([]string{"123A", "123B"}, "Google", "Cisco")
	if err != nil {
		t.Fatalf("unable to generate server artifacts: %v", err)
	}
	ctx := context.Background()
	encodedServerTrustCert := base64.StdEncoding.EncodeToString(a.TrustAnchor.Raw)
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
			OsImageHash:   "e9:c0:f8:b5:75:cb:fc:b4:2a:b3:b7:8e:cc:87:ef:a3:b0:11:d9:a5:d1:0b:09:fa:4e:96:f2:40:bf:6a:82:f5",
			HashAlgorithm: "ietf-sztp-conveyed-info:sha-256",
		},
		ControllerCards: []*epb.ControlCard{
			{
				SerialNumber: "123A",
				PartNumber:   "123A",
				DhcpConfig:   &epb.DHCPConfig{},
			},
			{
				SerialNumber: "123B",
				PartNumber:   "123B",
				DhcpConfig:   &epb.DHCPConfig{},
			},
		},
	}
	tests := []struct {
		desc              string
		chassis           *service.Chassis
		controlCardSerial string
		want              *bpb.BootstrapDataResponse
		wantErr           bool
	}{{
		desc:              "Success",
		controlCardSerial: "123",
		chassis: &service.Chassis{
			Serial: "123",
			SoftwareImage: &bpb.SoftwareImage{
				Name:          "Default Image",
				Version:       "1.0",
				Url:           "https://path/to/image",
				OsImageHash:   "e9:c0:f8:b5:75:cb:fc:b4:2a:b3:b7:8e:cc:87:ef:a3:b0:11:d9:a5:d1:0b:09:fa:4e:96:f2:40:bf:6a:82:f5",
				HashAlgorithm: "ietf-sztp-conveyed-info:sha-256",
			},
			BootloaderPasswordHash: "ABCD123",
			BootConfig: &bpb.BootConfig{
				VendorConfig: []byte(""),
				OcConfig:     []byte(""),
			},
			Authz: &apb.UploadRequest{
				Version:   "v0.1694813669807611349",
				CreatedOn: 1694813669807,
				Policy:    "{\"name\":\"default\",\"request\":{\"paths\":[\"*\"]},\"source\":{\"principals\":[\"cafyauto\"]}}",
			},
		},
		want: &bpb.BootstrapDataResponse{
			SerialNum: "123",
			IntendedImage: &bpb.SoftwareImage{
				Name:          "Default Image",
				Version:       "1.0",
				Url:           "https://path/to/image",
				OsImageHash:   "e9:c0:f8:b5:75:cb:fc:b4:2a:b3:b7:8e:cc:87:ef:a3:b0:11:d9:a5:d1:0b:09:fa:4e:96:f2:40:bf:6a:82:f5",
				HashAlgorithm: "ietf-sztp-conveyed-info:sha-256",
			},
			BootPasswordHash: "ABCD123",
			ServerTrustCert:  encodedServerTrustCert,
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
	},
	}

	em, err := New("", a)
	if err != nil {
		t.Fatalf("unable to create entitymanager: %v", err)
	}
	em.chassisInventory = []*epb.Chassis{&chassis}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			got, err := em.GetBootstrapData(ctx, test.chassis, test.controlCardSerial)
			if (err != nil) != test.wantErr {
				t.Errorf("GetBootstrapData(%v) err = %v, want %v", test.chassis, err, test.wantErr)
			}
			if diff := cmp.Diff(got, test.want, protocmp.Transform()); diff != "" {
				t.Errorf("GetBootstrapData(%v) diff = %v", test.chassis, diff)
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
		name        string
		inventory   []*epb.Chassis
		lookup      *service.EntityLookup
		wantChassis *epb.Chassis
		wantErr     string
	}{
		{
			name:   "Successfully GetDevice",
			lookup: &service.EntityLookup{SerialNumber: "1234", Manufacturer: "cisco"},
			inventory: []*epb.Chassis{
				{
					SerialNumber: "1234",
					Manufacturer: "cisco",
				},
			},
			wantChassis: &epb.Chassis{
				SerialNumber: "1234",
				Manufacturer: "cisco",
			},
			wantErr: "",
		},
		{
			name:   "Unsuccessfully GetDevice",
			lookup: &service.EntityLookup{SerialNumber: "1234", Manufacturer: "cisco"},
			inventory: []*epb.Chassis{
				{
					SerialNumber: "5678",
					Manufacturer: "sysco",
				},
			},
			wantChassis: nil,
			wantErr:     "could not find chassis for lookup",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			em := InMemoryEntityManager{
				chassisInventory: tt.inventory,
			}

			got, err := em.GetDevice(tt.lookup)

			if s := errdiff.Check(err, tt.wantErr); s != "" {
				t.Errorf("Expected error %s, but got error %v", tt.wantErr, err)
			} else if !(proto.Equal(tt.wantChassis, got)) {
				t.Errorf("Result of GetDevice does not match expected\nwant:\n\t%s\nactual:\n\t%s", tt.wantChassis, got)
			}
		})
	}
}

func TestGetAll(t *testing.T) {
	tests := []struct {
		inventory []*epb.Chassis
		name      string
	}{
		{
			name: "Successful GetAll",
			inventory: []*epb.Chassis{
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			em := InMemoryEntityManager{
				chassisInventory: tt.inventory,
			}
			got := em.GetAll()

			if !(cmp.Equal(tt.inventory, got, protocmp.Transform())) {
				t.Errorf("Result of GetDevice does not match expected\nwant:\n\t%s\nactual:\n\t%s", tt.inventory, got)
			}
		})
	}
}

func TestReplaceDevice(t *testing.T) {
	tests := []struct {
		inventory     []*epb.Chassis
		wantInventory []*epb.Chassis
		lookup        *service.EntityLookup
		name          string
		newChassis    *epb.Chassis
		wantErr       string
	}{
		{
			name: "Successfully ReplaceDevice",
			inventory: []*epb.Chassis{
				{
					SerialNumber: "1234",
					Manufacturer: "cisco",
				},
			},
			lookup: &service.EntityLookup{SerialNumber: "1234", Manufacturer: "cisco"},
			newChassis: &epb.Chassis{
				SerialNumber: "5678",
				Manufacturer: "cisco",
			},
			wantInventory: []*epb.Chassis{
				{
					SerialNumber: "5678",
					Manufacturer: "cisco",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			em := InMemoryEntityManager{
				chassisInventory: tt.inventory,
			}

			err := em.ReplaceDevice(tt.lookup, tt.newChassis)
			got := em.chassisInventory

			// todo: This test will require error checking after ValidateConfig is implemented.

			if s := errdiff.Check(err, tt.wantErr); s != "" {
				t.Errorf("Expected error %s, but got error %v", tt.wantErr, err)
			} else if !(cmp.Equal(tt.inventory, got, protocmp.Transform())) {
				t.Errorf("Result of ReplaceDevice does not match expected\nwant:\n\t%s\nactual:\n\t%s", tt.inventory, got)
			}
		})
	}
}

func TestDeleteDevice(t *testing.T) {
	tests := []struct {
		inventory     []*epb.Chassis
		wantInventory []*epb.Chassis
		lookup        *service.EntityLookup
		name          string
	}{
		{
			name: "Successfully DeleteDevice",
			inventory: []*epb.Chassis{
				{
					SerialNumber: "1234",
					Manufacturer: "cisco",
				},
			},
			lookup:        &service.EntityLookup{SerialNumber: "1234", Manufacturer: "cisco"},
			wantInventory: []*epb.Chassis{},
		},
		{
			name: "DeleteDevice nonexistent",
			inventory: []*epb.Chassis{
				{
					SerialNumber: "5678",
					Manufacturer: "cisco",
				},
			},
			lookup: &service.EntityLookup{SerialNumber: "1234", Manufacturer: "cisco"},
			wantInventory: []*epb.Chassis{
				{
					SerialNumber: "5678",
					Manufacturer: "cisco",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			em := InMemoryEntityManager{
				chassisInventory: tt.inventory,
			}

			em.DeleteDevice(tt.lookup)

			if !(cmp.Equal(tt.wantInventory, em.chassisInventory, protocmp.Transform())) {
				t.Errorf("Result of DeleteDevice does not match expected\nwant:\n\t%s\nactual:\n\t%s", tt.wantInventory, em.chassisInventory)
			}
		})
	}
}
