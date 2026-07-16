// Copyright 2026 Google LLC
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

package chassismanager

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/openconfig/bootz/common/types"
	"github.com/openconfig/gnsi/authz"
	"github.com/openconfig/gnsi/pathz"
	"google.golang.org/protobuf/testing/protocmp"

	bpb "github.com/openconfig/bootz/proto/bootz"
	cpb "github.com/openconfig/bootz/server/proto/config"
)

func TestInMemoryChassisManager(t *testing.T) {
	ctx := context.Background()

	// 1. Setup Test Data
	serial1 := "serial-123"
	serial2 := "serial-456"
	serialNotFound := "serial-999"

	hostname := "test-hostname"
	bootMode := bpb.BootMode_BOOT_MODE_SECURE
	streamingSupported := true
	manufacturer := "test-manufacturer"
	bootPasswordHash := "test-password-hash"
	skipIDevID := true

	intendedImage := &bpb.SoftwareImage{
		Version: "1.2.3",
		Url:     "http://example.com/image",
	}
	bootConfig := &bpb.BootConfig{
		VendorConfig: []byte("test-vendor-config"),
	}
	credentials := &bpb.Credentials{
		Passwords: nil,
	}
	pathzReq := &pathz.UploadRequest{}
	authzReq := &authz.UploadRequest{}
	certzProfiles := &bpb.CertzProfiles{}

	config := &cpb.Config{
		Chassis: []*cpb.Chassis{
			{
				Manufacturer:               manufacturer,
				Hostname:                   hostname,
				BootMode:                   bootMode,
				StreamingSupported:         streamingSupported,
				IntendedImage:              intendedImage,
				BootPasswordHash:           bootPasswordHash,
				BootConfig:                 bootConfig,
				Credentials:                credentials,
				Pathz:                      pathzReq,
				Authz:                      authzReq,
				CertzProfiles:              certzProfiles,
				SkipIdevidSerialValidation: skipIDevID,
				ControlCards: []*cpb.ControlCard{
					{
						SerialNumber: serial1,
					},
					{
						SerialNumber: serial2,
					},
				},
			},
		},
	}

	// 2. Initialize Chassis Manager
	manager := New(config)

	// 3. Test ResolveChassis
	t.Run("ResolveChassis Success", func(t *testing.T) {
		ch := &types.Chassis{
			ActiveSerial: serial1,
		}
		err := manager.ResolveChassis(ctx, ch)
		if err != nil {
			t.Fatalf("ResolveChassis failed: %v", err)
		}

		want := &types.Chassis{
			ActiveSerial:               serial1,
			Hostname:                   hostname,
			BootMode:                   bootMode,
			StreamingSupported:         streamingSupported,
			Manufacturer:               manufacturer,
			SkipIDevIDSerialValidation: skipIDevID,
		}
		if diff := cmp.Diff(want, ch, protocmp.Transform()); diff != "" {
			t.Errorf("ResolveChassis() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("ResolveChassis Nil Chassis", func(t *testing.T) {
		err := manager.ResolveChassis(ctx, nil)
		if err == nil {
			t.Errorf("ResolveChassis on nil chassis succeeded, want error")
		}
	})

	t.Run("ResolveChassis Not Found", func(t *testing.T) {
		ch := &types.Chassis{
			ActiveSerial: serialNotFound,
		}
		err := manager.ResolveChassis(ctx, ch)
		if err == nil {
			t.Errorf("ResolveChassis with unknown serial succeeded, want error")
		}
	})

	// 4. Test GenerateBootstrapData
	t.Run("GenerateBootstrapData Success", func(t *testing.T) {
		serials := []string{serial1, serial2}
		responses, err := manager.GenerateBootstrapData(ctx, nil, serials)
		if err != nil {
			t.Fatalf("GenerateBootstrapData failed: %v", err)
		}

		if len(responses) != len(serials) {
			t.Fatalf("GenerateBootstrapData got %d responses, want %d", len(responses), len(serials))
		}

		for i, serial := range serials {
			resp := responses[i]
			if resp.SerialNum != serial {
				t.Errorf("GenerateBootstrapData[%d] got serial %q, want %q", i, resp.SerialNum, serial)
			}
			if diff := cmp.Diff(resp.IntendedImage, intendedImage, protocmp.Transform()); diff != "" {
				t.Errorf("GenerateBootstrapData[%d] IntendedImage diff (-got +want):\n%s", i, diff)
			}
			if resp.BootPasswordHash != bootPasswordHash {
				t.Errorf("GenerateBootstrapData[%d] got BootPasswordHash %q, want %q", i, resp.BootPasswordHash, bootPasswordHash)
			}
			if diff := cmp.Diff(resp.BootConfig, bootConfig, protocmp.Transform()); diff != "" {
				t.Errorf("GenerateBootstrapData[%d] BootConfig diff (-got +want):\n%s", i, diff)
			}
			if diff := cmp.Diff(resp.Credentials, credentials, protocmp.Transform()); diff != "" {
				t.Errorf("GenerateBootstrapData[%d] Credentials diff (-got +want):\n%s", i, diff)
			}
			if diff := cmp.Diff(resp.Pathz, pathzReq, protocmp.Transform()); diff != "" {
				t.Errorf("GenerateBootstrapData[%d] Pathz diff (-got +want):\n%s", i, diff)
			}
			if diff := cmp.Diff(resp.Authz, authzReq, protocmp.Transform()); diff != "" {
				t.Errorf("GenerateBootstrapData[%d] Authz diff (-got +want):\n%s", i, diff)
			}
			if diff := cmp.Diff(resp.CertzProfiles, certzProfiles, protocmp.Transform()); diff != "" {
				t.Errorf("GenerateBootstrapData[%d] CertzProfiles diff (-got +want):\n%s", i, diff)
			}
		}
	})

	t.Run("GenerateBootstrapData Not Found", func(t *testing.T) {
		serials := []string{serial1, serialNotFound}
		_, err := manager.GenerateBootstrapData(ctx, nil, serials)
		if err == nil {
			t.Errorf("GenerateBootstrapData with unknown serial succeeded, want error")
		}
	})

	// 5. Test UpdateStatus
	t.Run("UpdateStatus Success", func(t *testing.T) {
		req := &bpb.ReportStatusRequest{
			Status:        bpb.ReportStatusRequest_BOOTSTRAP_STATUS_SUCCESS,
			StatusMessage: "test status message",
			States: []*bpb.ControlCardState{
				{
					SerialNumber: serial1,
					Status:       bpb.ControlCardState_CONTROL_CARD_STATUS_INITIALIZED,
				},
			},
		}
		err := manager.UpdateStatus(ctx, req)
		if err != nil {
			t.Errorf("UpdateStatus failed: %v", err)
		}
	})

	t.Run("UpdateStatus No States", func(t *testing.T) {
		req := &bpb.ReportStatusRequest{
			Status:        bpb.ReportStatusRequest_BOOTSTRAP_STATUS_SUCCESS,
			StatusMessage: "test status message",
		}
		err := manager.UpdateStatus(ctx, req)
		if err == nil {
			t.Errorf("UpdateStatus with no states succeeded, want error")
		}
	})
}
