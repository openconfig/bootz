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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/openconfig/bootz/common/types"
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
		want    *types.EntityLookup
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
			want: &types.EntityLookup{
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
			want: &types.EntityLookup{
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

// Mock EntityManager for testing purposes.
type mockEntityManager struct {
	resolveChassisResp   *types.Chassis
	resolveChassisErr    error
	getBootstrapDataResp *bpb.BootstrapDataResponse
	getBootstrapDataErr  error
	setStatusErr         error
	signErr              error
}

func (m *mockEntityManager) ResolveChassis(context.Context, *types.EntityLookup, string) (*types.Chassis, error) {
	return m.resolveChassisResp, m.resolveChassisErr
}
func (m *mockEntityManager) GetBootstrapData(context.Context, *types.Chassis, string) (*bpb.BootstrapDataResponse, error) {
	return m.getBootstrapDataResp, m.getBootstrapDataErr
}
func (m *mockEntityManager) SetStatus(context.Context, *bpb.ReportStatusRequest) error {
	return m.setStatusErr
}
func (m *mockEntityManager) Sign(context.Context, *bpb.GetBootstrapDataResponse, *types.Chassis, string) error {
	return m.signErr
}

// Helper function to create a dummy X509 certificate
func createTestCertificate(t *testing.T, commonName string, serialNumber string) (*rsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   commonName,
			SerialNumber: serialNumber,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}
	return priv, derBytes
}

func startTestServer(t *testing.T, srv *grpc.Server) string {
	t.Helper()
	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)
	return lis.Addr().String()
}

func createTestClient(t *testing.T, addr string, tlsClientCreds credentials.TransportCredentials) *grpc.ClientConn {
	t.Helper()
	opts := []grpc.DialOption{}
	if tlsClientCreds != nil {
		opts = append(opts, grpc.WithTransportCredentials(tlsClientCreds))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
	conn, err := grpc.Dial(addr, opts...)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func TestBootstrapStream(t *testing.T) {
	devicePrivKey, goodCertDER := createTestCertificate(t, "test-device", "test-serial-123")
	goodCert := base64.StdEncoding.EncodeToString(goodCertDER)

	tests := []struct {
		name         string
		em           *mockEntityManager
		initialReq   *bpb.BootstrapStreamRequest
		wantErrCode  codes.Code
		signedNonce  []byte
		reportStatus bool
	}{
		{
			name: "IDevID Flow Success - Initial Challenge Only",
			em: &mockEntityManager{
				resolveChassisResp: &types.Chassis{Serial: "test-serial-123"},
			},
			initialReq: &bpb.BootstrapStreamRequest{
				Type: &bpb.BootstrapStreamRequest_BootstrapRequest{
					BootstrapRequest: &bpb.GetBootstrapDataRequest{
						ChassisDescriptor: &bpb.ChassisDescriptor{SerialNumber: "test-serial-123", PartNumber: "FIXED-123"},
						ControlCardState:  &bpb.ControlCardState{SerialNumber: "test-serial-123"},
						Identity:          &bpb.Identity{Type: &bpb.Identity_IdevidCert{IdevidCert: goodCert}},
					},
				},
			},
			// A nil signedNonce indicates this test only covers the initial request/response.
			signedNonce: nil,
		},
		{
			name: "IDevID Flow Success - Full End-to-End",
			em: &mockEntityManager{
				resolveChassisResp: &types.Chassis{Serial: "test-serial-123"},
				getBootstrapDataResp: &bpb.BootstrapDataResponse{
					BootConfig: &bpb.BootConfig{
						VendorConfig: []byte("test-vendor-config"),
					},
				},
			},
			initialReq: &bpb.BootstrapStreamRequest{
				Type: &bpb.BootstrapStreamRequest_BootstrapRequest{
					BootstrapRequest: &bpb.GetBootstrapDataRequest{
						ChassisDescriptor: &bpb.ChassisDescriptor{SerialNumber: "test-serial-123", PartNumber: "FIXED-SUCCESS"},
						ControlCardState:  &bpb.ControlCardState{SerialNumber: "test-serial-123"},
						Identity:          &bpb.Identity{Type: &bpb.Identity_IdevidCert{IdevidCert: goodCert}},
					},
				},
			},
			// An empty slice indicates a valid signature should be computed.
			signedNonce: []byte{},
		},
		{
			name: "IDevID Flow Failure - Invalid Signature",
			em: &mockEntityManager{
				resolveChassisResp: &types.Chassis{Serial: "test-serial-123"},
			},
			initialReq: &bpb.BootstrapStreamRequest{
				Type: &bpb.BootstrapStreamRequest_BootstrapRequest{
					BootstrapRequest: &bpb.GetBootstrapDataRequest{
						ChassisDescriptor: &bpb.ChassisDescriptor{SerialNumber: "test-serial-123", PartNumber: "FIXED-FAILURE"},
						ControlCardState:  &bpb.ControlCardState{SerialNumber: "test-serial-123"},
						Identity:          &bpb.Identity{Type: &bpb.Identity_IdevidCert{IdevidCert: goodCert}},
					},
				},
			},
			// A non-empty, non-nil slice indicates a bad signature.
			signedNonce: []byte("this is not a valid signature"),
		},
		{
			name: "Missing Identity - Invalid Argument",
			em:   &mockEntityManager{},
			initialReq: &bpb.BootstrapStreamRequest{
				Type: &bpb.BootstrapStreamRequest_BootstrapRequest{
					BootstrapRequest: &bpb.GetBootstrapDataRequest{},
				},
			},
			wantErrCode: codes.InvalidArgument,
		},
		{
			name: "IDevID Flow with Successful Status Report",
			em: &mockEntityManager{
				resolveChassisResp: &types.Chassis{Serial: "test-serial-123"},
				getBootstrapDataResp: &bpb.BootstrapDataResponse{
					BootConfig: &bpb.BootConfig{VendorConfig: []byte("test-vendor-config")},
				},
			},
			initialReq: &bpb.BootstrapStreamRequest{
				Type: &bpb.BootstrapStreamRequest_BootstrapRequest{
					BootstrapRequest: &bpb.GetBootstrapDataRequest{
						ChassisDescriptor: &bpb.ChassisDescriptor{SerialNumber: "test-serial-123", PartNumber: "FIXED-SUCCESS-STATUS"},
						ControlCardState:  &bpb.ControlCardState{SerialNumber: "test-serial-123"},
						Identity:          &bpb.Identity{Type: &bpb.Identity_IdevidCert{IdevidCert: goodCert}},
					},
				},
			},
			signedNonce:  []byte{},
			reportStatus: true,
		},
		{
			name: "IDevID Flow with Failing Status Report",
			em: &mockEntityManager{
				resolveChassisResp: &types.Chassis{Serial: "test-serial-123"},
				getBootstrapDataResp: &bpb.BootstrapDataResponse{
					BootConfig: &bpb.BootConfig{VendorConfig: []byte("test-vendor-config")},
				},
				setStatusErr: status.Errorf(codes.Internal, "db error"),
			},
			initialReq: &bpb.BootstrapStreamRequest{
				Type: &bpb.BootstrapStreamRequest_BootstrapRequest{
					BootstrapRequest: &bpb.GetBootstrapDataRequest{
						ChassisDescriptor: &bpb.ChassisDescriptor{SerialNumber: "test-serial-123", PartNumber: "FIXED-FAIL-STATUS"},
						ControlCardState:  &bpb.ControlCardState{SerialNumber: "test-serial-123"},
						Identity:          &bpb.Identity{Type: &bpb.Identity_IdevidCert{IdevidCert: goodCert}},
					},
				},
			},
			signedNonce:  []byte{},
			reportStatus: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := New(test.em)
			srv := grpc.NewServer(grpc.Creds(insecure.NewCredentials()))
			bpb.RegisterBootstrapServer(srv, s)
			addr := startTestServer(t, srv)
			conn := createTestClient(t, addr, nil)
			cli := bpb.NewBootstrapClient(conn)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			stream, err := cli.BootstrapStream(ctx)
			if err != nil {
				t.Fatalf("BootstrapStream() failed: %v", err)
			}

			if err := stream.Send(test.initialReq); err != nil {
				t.Fatalf("stream.Send(%v) failed: %v", test.initialReq, err)
			}

			// === First Recv: Expect Challenge or Error ===
			resp, err := stream.Recv()

			if test.wantErrCode != codes.OK {
				if err == nil {
					t.Errorf("stream.Recv() got response %v, want error code %v", resp, test.wantErrCode)
				} else if stat, ok := status.FromError(err); ok && stat.Code() != test.wantErrCode {
					t.Errorf("stream.Recv() got error code %v, want %v: %v", stat.Code(), test.wantErrCode, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("stream.Recv() got unexpected error %v", err)
			}
			challenge := resp.GetChallenge()
			if challenge == nil {
				t.Fatalf("Response missing challenge")
			}
			nonceStr := challenge.GetNonce()
			if nonceStr == "" {
				t.Errorf("Challenge missing nonce")
			}
			nonce, err := base64.StdEncoding.DecodeString(nonceStr)
			if err != nil {
				t.Fatalf("Nonce is not valid base64: %v", err)
			}

			// If signedNonce is nil, the test ends here.
			if test.signedNonce == nil {
				stream.CloseSend()
				_, err = stream.Recv()
				if err != io.EOF {
					t.Errorf("Expected EOF after response, got %v", err)
				}
				return
			}

			// === Second Send: Respond with Signed Nonce ===
			var finalSignedNonce []byte
			if len(test.signedNonce) == 0 {
				// If signedNonce is an empty slice, compute a valid one.
				hasher := sha256.New()
				hasher.Write(nonce)
				hashedNonce := hasher.Sum(nil)
				finalSignedNonce, err = rsa.SignPKCS1v15(rand.Reader, devicePrivKey, crypto.SHA256, hashedNonce)
				if err != nil {
					t.Fatalf("Failed to sign nonce: %v", err)
				}
			} else {
				// Otherwise, use the value from the test case.
				finalSignedNonce = test.signedNonce
			}

			responseReq := &bpb.BootstrapStreamRequest{
				Type: &bpb.BootstrapStreamRequest_Response_{
					Response: &bpb.BootstrapStreamRequest_Response{
						Type: &bpb.BootstrapStreamRequest_Response_NonceSigned{NonceSigned: finalSignedNonce},
					},
				},
			}
			if err := stream.Send(responseReq); err != nil {
				t.Fatalf("stream.Send(responseReq) failed: %v", err)
			}

			// === Second Recv: Expect Bootstrap Data or Error ===
			finalResp, err := stream.Recv()

			// Infer the expected final outcome based on the signedNonce value.
			if len(test.signedNonce) > 0 { // A non-empty slice implies a bad signature.
				if err == nil {
					t.Fatalf("stream.Recv() got final response %v, want error code %v", finalResp, codes.InvalidArgument)
				}
				if stat, _ := status.FromError(err); stat.Code() != codes.InvalidArgument {
					t.Fatalf("stream.Recv() got final error code %v, want %v: %v", stat.Code(), codes.InvalidArgument, err)
				}
				return
			}

			// An empty slice implies a successful bootstrap.
			if err != nil {
				t.Fatalf("stream.Recv() for final response got unexpected error: %v", err)
			}
			bootstrapWrapper := finalResp.GetBootstrapResponse()
			if bootstrapWrapper == nil {
				t.Fatalf("Expected bootstrap response, but got: %v", finalResp)
			}
			if bootstrapWrapper.GetSerializedBootstrapData() == nil {
				t.Error("Final response is missing the serialized bootstrap data")
			}

			// === Optional Third Stage: Status Reporting ===
			if test.reportStatus {
				statusReq := &bpb.BootstrapStreamRequest{
					Type: &bpb.BootstrapStreamRequest_ReportStatusRequest{
						ReportStatusRequest: &bpb.ReportStatusRequest{
							Status: bpb.ReportStatusRequest_BOOTSTRAP_STATUS_SUCCESS,
						},
					},
				}
				if err := stream.Send(statusReq); err != nil {
					t.Fatalf("stream.Send(statusReq) failed: %v", err)
				}

				ack, err := stream.Recv()
				if test.em.setStatusErr != nil {
					if err == nil {
						t.Fatalf("Expected error on status report, got %v", ack)
					}
					if s, _ := status.FromError(err); s.Code() != codes.Internal {
						t.Errorf("Expected Internal error, got %v", s.Code())
					}
					return
				}

				if err != nil {
					t.Fatalf("Got unexpected error on status report: %v", err)
				}
				if ack.GetReportStatusResponse() == nil {
					t.Fatalf("Expected ReportStatusResponse, got %T", ack.Type)
				}
			}

			stream.CloseSend()
			_, err = stream.Recv()
			if err != io.EOF {
				t.Errorf("Expected EOF after final response, got %v", err)
			}
		})
	}
}
