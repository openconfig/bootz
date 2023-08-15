package entitymanager

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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
	}{
		{
			desc:    "Missing OV",
			serial:  "123B",
			wantErr: true,
		},
		{
			desc:    "Found OV",
			serial:  "123A",
			want:    "test_ov",
			wantErr: false,
		},
	}

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
	}{
		{
			desc: "Default device",
			input: &service.EntityLookup{
				SerialNumber: "123",
				Manufacturer: "Cisco",
			},
			want: &service.ChassisEntity{
				BootMode: bootz.BootMode_BOOT_MODE_SECURE,
			},
		},
		{
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
		resp    *bootz.GetBootstrapDataResponse
		wantErr bool
	}{
		{
			desc: "Success",
			resp: &bootz.GetBootstrapDataResponse{
				SignedResponse: &bootz.BootstrapDataSigned{
					Responses: []*bootz.BootstrapDataResponse{
						{SerialNum: "123A"},
					},
				},
			},
			wantErr: false,
		},
		{
			desc:    "Empty response",
			resp:    &bootz.GetBootstrapDataResponse{},
			wantErr: true,
		},
	}

	em := New(nil)
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			err := em.Sign(test.resp, priv)
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
			err = rsa.VerifyPKCS1v15(&priv.PublicKey, crypto.SHA256, hashed[:], []byte(test.resp.GetResponseSignature()))
			if err != nil {
				t.Errorf("Sign() err == %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestSetStatus(t *testing.T) {
	tests := []struct {
		desc    string
		input   *bootz.ReportStatusRequest
		wantErr bool
	}{
		{
			desc: "No control card states",
			input: &bootz.ReportStatusRequest{
				Status:        bootz.ReportStatusRequest_BOOTSTRAP_STATUS_SUCCESS,
				StatusMessage: "Bootstrap status succeeded",
			},
			wantErr: true,
		},
		{
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
		},
		{
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
	}{
		{
			desc:    "No serial number",
			input:   &bootz.ControlCard{},
			wantErr: true,
		},
		{
			desc: "Control card not found",
			input: &bootz.ControlCard{
				SerialNumber: "456A",
			},
			wantErr: true,
		},
		{
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
