// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package service

import (
	"context"
	"net"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/grpc/peer"

	bpb "github.com/openconfig/bootz/proto/bootz"
)

func peerAddressContext(t *testing.T, address string) context.Context {
	t.Helper()
	return peer.NewContext(context.Background(), &peer.Peer{
		Addr: &net.TCPAddr{
			IP: net.ParseIP(address),
		},
	})
}

func TestBuildEntityLookup(t *testing.T) {
	tests := []struct {
		name    string
		ctx     context.Context
		req     *bpb.GetBootstrapDataRequest
		want    *EntityLookup
		wantErr bool
	}{
		{
			name: "Successful fixed-form factor",
			ctx:  peerAddressContext(t, "1.1.1.1"),
			req: &bpb.GetBootstrapDataRequest{
				ChassisDescriptor: &bpb.ChassisDescriptor{
					Manufacturer: "Cisco",
					SerialNumber: "1234",
					PartNumber:   "ABC",
				},
				ControlCardState: &bpb.ControlCardState{
					SerialNumber: "1234",
				},
			},
			want: &EntityLookup{
				Manufacturer: "Cisco",
				SerialNumber: "1234",
				PartNumber:   "ABC",
				IPAddress:    "1.1.1.1",
				Modular:      false,
			},
			wantErr: false,
		},
		{
			name: "Successful modular device",
			ctx:  peerAddressContext(t, "1.1.1.1"),
			req: &bpb.GetBootstrapDataRequest{
				ChassisDescriptor: &bpb.ChassisDescriptor{
					Manufacturer: "Cisco",
					ControlCards: []*bpb.ControlCard{
						{
							SerialNumber: "1234a",
							PartNumber:   "ABCa",
						},
					},
				},
				ControlCardState: &bpb.ControlCardState{
					SerialNumber: "1234a",
				},
			},
			want: &EntityLookup{
				Manufacturer: "Cisco",
				SerialNumber: "1234a",
				PartNumber:   "ABCa",
				IPAddress:    "1.1.1.1",
				Modular:      true,
			},
			wantErr: false,
		},
		{
			name: "Modular chassis descriptor contains wrong control card",
			ctx:  peerAddressContext(t, "1.1.1.1"),
			req: &bpb.GetBootstrapDataRequest{
				ChassisDescriptor: &bpb.ChassisDescriptor{
					Manufacturer: "Cisco",
					ControlCards: []*bpb.ControlCard{
						{
							SerialNumber: "1234b",
							PartNumber:   "ABCb",
						},
					},
				},
				ControlCardState: &bpb.ControlCardState{
					SerialNumber: "1234a",
				},
			},
			wantErr: true,
		},
		{
			name: "Fixed form factor device has no part number",
			ctx:  peerAddressContext(t, "1.1.1.1"),
			req: &bpb.GetBootstrapDataRequest{
				ChassisDescriptor: &bpb.ChassisDescriptor{
					Manufacturer: "Cisco",
					SerialNumber: "1234",
				},
				ControlCardState: &bpb.ControlCardState{
					SerialNumber: "12344",
				},
			},
			wantErr: true,
		},
		{
			name: "Fixed form factor does not set active control card",
			ctx:  peerAddressContext(t, "1.1.1.1"),
			req: &bpb.GetBootstrapDataRequest{
				ChassisDescriptor: &bpb.ChassisDescriptor{
					Manufacturer: "Cisco",
					SerialNumber: "1234",
					PartNumber:   "ABC",
				},
			},
			wantErr: true,
		},
		{
			name:    "No address in context",
			ctx:     context.Background(),
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := buildEntityLookup(tc.ctx, tc.req)
			if err != nil {
				if tc.wantErr {
					return
				}
				t.Fatalf("buildEntityLookup err = %v, want nil", err)
			}
			if diff := cmp.Diff(got, tc.want); diff != "" {
				t.Errorf("buildEntityLookup diff = %v", diff)
			}
		})
	}
}
