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
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/hpke"
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
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/go-tpm/tpm2"
	"github.com/openconfig/attestz/service/biz"
	"github.com/openconfig/bootz/common/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	epb "github.com/openconfig/attestz/proto/tpm_enrollz"
	bpb "github.com/openconfig/bootz/proto/bootz"
)

var (
	testOV            = []byte("test-ov")
	testOC            = []byte("test-oc")
	testSig           = "test-signature"
	testNonce         = "test-client-nonce"
	testBootstrapData = &bpb.BootstrapDataResponse{BootConfig: &bpb.BootConfig{VendorConfig: []byte("test-vendor-config")}}
)

// Mock EntityManager for testing purposes.
type mockEntityManager struct {
	resolveChassisResp   *types.Chassis
	resolveChassisErr    error
	getBootstrapDataResp *bpb.BootstrapDataResponse
	getBootstrapDataErr  error
	setStatusErr         error
	signErr              error
}

func (m *mockEntityManager) ResolveChassis(ctx context.Context, chassis *types.Chassis) error {
	chassisCopy := *chassis
	*chassis = *m.resolveChassisResp
	chassis.Serials = chassisCopy.Serials
	chassis.ActiveSerial = chassisCopy.ActiveSerial
	chassis.IPAddress = chassisCopy.IPAddress
	chassis.Identity = chassisCopy.Identity
	return m.resolveChassisErr
}
func (m *mockEntityManager) GetBootstrapData(context.Context, *types.Chassis, string) (*bpb.BootstrapDataResponse, error) {
	return m.getBootstrapDataResp, m.getBootstrapDataErr
}
func (m *mockEntityManager) SetStatus(context.Context, *bpb.ReportStatusRequest) error {
	return m.setStatusErr
}
func (m *mockEntityManager) Sign(context.Context, []byte, *types.Chassis) (string, []byte, []byte, error) {
	return testSig, testOV, testOC, m.signErr
}
func (m *mockEntityManager) ValidateIDevID(context.Context, *x509.Certificate, []byte, *types.Chassis) error {
	return m.signErr
}

type mockTPM20Utils struct {
	errGenerate error
	errWrap     error
	errVerify   error
}

func (m *mockTPM20Utils) GenerateRestrictedHMACKey() (*tpm2.TPMTPublic, *tpm2.TPMTSensitive, error) {
	return &tpm2.RSAEKTemplate, &tpm2.TPMTSensitive{}, m.errGenerate
}
func (m *mockTPM20Utils) WrapHMACKeytoRSAPublicKey(rsaPub *rsa.PublicKey, hmacPub *tpm2.TPMTPublic, hmacSensitive *tpm2.TPMTSensitive) ([]byte, []byte, error) {
	return []byte("message"), []byte("signature"), m.errWrap
}
func (m *mockTPM20Utils) ParseTCGCSRIDevIDContent(csrBytes []byte) (*biz.TCGCSRIDevIDContents, error) {
	return nil, nil
}
func (m *mockTPM20Utils) TPMTPublicToPEM(pubKey *tpm2.TPMTPublic) (string, error) {
	return "", nil
}
func (m *mockTPM20Utils) RSAEKPublicKeyToTPMTPublic(rsaPublicKey *rsa.PublicKey) (*tpm2.TPMTPublic, error) {
	return nil, nil
}
func (m *mockTPM20Utils) VerifyHMAC(message []byte, signature []byte, hmacSensitive *tpm2.TPMTSensitive) error {
	return m.errVerify
}
func (m *mockTPM20Utils) VerifyCertifyInfo(certifyInfoAttest *tpm2.TPMSAttest, certifiedKey *tpm2.TPMTPublic) error {
	return nil
}
func (m *mockTPM20Utils) VerifyIAKAttributes(iakPub []byte) (*tpm2.TPMTPublic, error) {
	return nil, nil
}
func (m *mockTPM20Utils) VerifyTPMTSignature(data []byte, signature *tpm2.TPMTSignature, pubKey *tpm2.TPMTPublic) error {
	return nil
}
func (m *mockTPM20Utils) VerifyIdevidAttributes(idevidPub *tpm2.TPMTPublic, keyTemplate epb.KeyTemplate) error {
	return nil
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
	ekPub := &rsa.PublicKey{N: big.NewInt(123456789), E: 65537}
	em := &mockEntityManager{
		resolveChassisResp:   &types.Chassis{StreamingSupported: true, ActivePublicKey: ekPub, ActivePublicKeyType: epb.Key_KEY_EK},
		getBootstrapDataResp: testBootstrapData,
	}
	initialReq := &bpb.BootstrapStreamRequest{
		Type: &bpb.BootstrapStreamRequest_BootstrapRequest{
			BootstrapRequest: &bpb.GetBootstrapDataRequest{
				ChassisDescriptor: &bpb.ChassisDescriptor{SerialNumber: "test-serial-123"},
				ControlCardState:  &bpb.ControlCardState{SerialNumber: "test-serial-123"},
			},
		},
	}
	statusReq := &bpb.BootstrapStreamRequest{
		Type: &bpb.BootstrapStreamRequest_ReportStatusRequest{
			ReportStatusRequest: &bpb.ReportStatusRequest{
				States: []*bpb.ControlCardState{
					{SerialNumber: "test-serial-123"},
				},
			},
		},
	}
	idIdevid := &bpb.Identity{Type: &bpb.Identity_IdevidCert{IdevidCert: goodCert}}
	idNoIdevid := &bpb.Identity{Type: &bpb.Identity_EkPpkPub{EkPpkPub: true}}

	tests := []struct {
		name         string
		em           *mockEntityManager
		tpm          *mockTPM20Utils
		req          *bpb.BootstrapStreamRequest
		id           *bpb.Identity
		wantErrCode  codes.Code
		signedNonce  []byte
		reportStatus bool
	}{
		{
			name: "IDevID Flow Success - Initial Challenge Only",
			em:   em,
			req:  initialReq,
			id:   idIdevid,
			// A nil signedNonce indicates this test only covers the initial request/response.
			signedNonce: nil,
		},
		{
			name: "IDevID Flow Success - Full End-to-End",
			em:   em,
			req:  initialReq,
			id:   idIdevid,
			// An empty slice indicates a valid signature should be computed.
			signedNonce: []byte{},
		},
		{
			name: "IDevID Flow Failure - Invalid Signature",
			em:   em,
			req:  initialReq,
			id:   idIdevid,
			// A non-empty, non-nil slice indicates a bad signature.
			signedNonce: []byte("this is not a valid signature"),
		},
		{
			name:        "Missing Identity - Invalid Argument",
			em:          &mockEntityManager{},
			req:         initialReq,
			wantErrCode: codes.InvalidArgument,
		},
		{
			name:         "IDevID Flow with Successful Status Report",
			em:           em,
			req:          initialReq,
			id:           idIdevid,
			signedNonce:  []byte{},
			reportStatus: true,
		},
		{
			name: "IDevID Flow with Failing Status Report",
			em: &mockEntityManager{
				resolveChassisResp:   &types.Chassis{StreamingSupported: true},
				getBootstrapDataResp: testBootstrapData,
				setStatusErr:         status.Errorf(codes.Internal, "db error"),
			},
			req:          initialReq,
			id:           idIdevid,
			signedNonce:  []byte{},
			reportStatus: true,
		},
		{
			name:        "IDevID Flow Re-authentication on new stream with Status Report",
			em:          em,
			req:         statusReq,
			id:          idIdevid,
			signedNonce: []byte{}, // valid signature
		},
		{
			name: "TPM 2.0 no-IDevID Flow Success - Full End-to-End",
			em:   em,
			tpm:  &mockTPM20Utils{},
			req:  initialReq,
			id:   idNoIdevid,
		},
		{
			name: "TPM 2.0 no-IDevID Re-authentication on new stream with Status Report",
			em:   em,
			tpm:  &mockTPM20Utils{},
			req:  statusReq,
			id:   idNoIdevid,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := New(test.em, test.tpm)
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

			req := proto.Clone(test.req).(*bpb.BootstrapStreamRequest)
			if test.id != nil {
				switch reqType := req.Type.(type) {
				case *bpb.BootstrapStreamRequest_BootstrapRequest:
					reqType.BootstrapRequest.Identity = test.id
				case *bpb.BootstrapStreamRequest_ReportStatusRequest:
					reqType.ReportStatusRequest.Identity = test.id
				}
			}

			if err := stream.Send(req); err != nil {
				t.Fatalf("stream.Send(%v) failed: %v", req, err)
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
			var responseReq *bpb.BootstrapStreamRequest
			switch challengeType := challenge.Type.(type) {
			case *bpb.BootstrapStreamResponse_Challenge_Nonce:
				nonce := challenge.GetNonce()
				if nonce == "" {
					t.Errorf("Challenge missing nonce")
				}

				// If signedNonce is nil, the test ends here.
				if test.signedNonce == nil {
					stream.CloseSend()
					_, err := stream.Recv()
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
					hasher.Write([]byte(nonce))
					hashedNonce := hasher.Sum(nil)
					finalSignedNonce, err = rsa.SignPKCS1v15(rand.Reader, devicePrivKey, crypto.SHA256, hashedNonce)
					if err != nil {
						t.Fatalf("Failed to sign nonce: %v", err)
					}
				} else {
					// Otherwise, use the value from the test case.
					finalSignedNonce = test.signedNonce
				}

				responseReq = &bpb.BootstrapStreamRequest{
					Type: &bpb.BootstrapStreamRequest_Response_{
						Response: &bpb.BootstrapStreamRequest_Response{
							Type: &bpb.BootstrapStreamRequest_Response_NonceSigned{NonceSigned: finalSignedNonce},
						},
					},
				}
			case *bpb.BootstrapStreamResponse_Challenge_Tpm20HmacChallenge:
				hmac := challenge.GetTpm20HmacChallenge()
				if hmac == nil {
					t.Errorf("Challenge missing HMAC")
				}
				if hmac.GetKey() != test.em.resolveChassisResp.ActivePublicKeyType {
					t.Errorf("Unexpected key type in challenge: got %v, want %v", hmac.GetKey(), test.em.resolveChassisResp.ActivePublicKeyType)
				}
				responseReq = &bpb.BootstrapStreamRequest{
					Type: &bpb.BootstrapStreamRequest_Response_{
						Response: &bpb.BootstrapStreamRequest_Response{
							Type: &bpb.BootstrapStreamRequest_Response_HmacChallengeResponse{
								HmacChallengeResponse: &epb.HMACChallengeResponse{
									IakPub: []byte("IAKPub"),
									IakCertifyInfo: tpm2.Marshal(tpm2.New2B(tpm2.TPMSAttest{
										Type:     tpm2.TPMSTAttestCertify,
										Attested: tpm2.NewTPMUAttest(tpm2.TPMSTAttestCertify, &tpm2.TPMSCertifyInfo{}),
									})),
									IakCertifyInfoSignature: []byte("IAKCertifySignature"),
								},
							},
						},
					},
				}
			default:
				t.Fatalf("Unexpected challenge type %T", challengeType)
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

			// Handle re-authentication flow initiated by a status report.
			if _, ok := test.req.Type.(*bpb.BootstrapStreamRequest_ReportStatusRequest); ok {
				if err != nil {
					t.Fatalf("stream.Recv() for re-auth response got unexpected error: %v", err)
				}
				if finalResp.GetReportStatusResponse() == nil {
					t.Fatalf("Expected report status response for re-auth, but got: %v", finalResp)
				}
				return // End of test for this case.
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

func TestBootstrapStreamV1(t *testing.T) {
	deviceKey, deviceCert := createTestCertificate(t, "test-device", "test-serial-123")
	idevidCert := base64.StdEncoding.EncodeToString(deviceCert)
	ekPub := &rsa.PublicKey{N: big.NewInt(123456789), E: 65537}
	idIdevid := &bpb.Identity{Type: &bpb.Identity_IdevidCert{IdevidCert: idevidCert}}
	idTPM20EK := &bpb.Identity{Type: &bpb.Identity_Tpm20EkPub{Tpm20EkPub: []byte{}}}
	hpkeKey, err := hpke.DHKEM(ecdh.X25519()).GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate HPKE key: %v", err)
	}
	transportKey := &bpb.TransportKey{
		CipherSuite: bpb.HPKECipherSuite_HPKE_CIPHER_SUITE_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM,
		PublicKey:   hpkeKey.PublicKey().Bytes(),
	}
	bootstrapData := &bpb.BootstrapDataSigned{
		Responses: []*bpb.BootstrapDataResponse{testBootstrapData},
		Nonce:     testNonce,
	}
	em := &mockEntityManager{
		resolveChassisResp:   &types.Chassis{StreamingSupported: true, ActivePublicKey: ekPub, ActivePublicKeyType: epb.Key_KEY_EK},
		getBootstrapDataResp: testBootstrapData,
	}
	initialReq := &bpb.BootstrapStreamRequestV1{
		Type: &bpb.BootstrapStreamRequestV1_BootstrapRequest{
			BootstrapRequest: &bpb.GetBootstrapDataRequest{
				ChassisDescriptor: &bpb.ChassisDescriptor{SerialNumber: "test-serial-123"},
				ControlCardState:  &bpb.ControlCardState{SerialNumber: "test-serial-123"},
				Nonce:             testNonce,
			},
		},
	}
	statusReq := &bpb.BootstrapStreamRequestV1{
		Type: &bpb.BootstrapStreamRequestV1_ReportStatusRequest{
			ReportStatusRequest: &bpb.ReportStatusRequest{
				States: []*bpb.ControlCardState{
					{SerialNumber: "test-serial-123"},
				},
			},
		},
	}

	tests := []struct {
		name      string
		em        *mockEntityManager
		tpm       *mockTPM20Utils
		req       *bpb.BootstrapStreamRequestV1
		id        *bpb.Identity
		wantCodes []codes.Code
	}{
		{
			name:      "Missing Identity - Invalid Argument",
			em:        &mockEntityManager{},
			req:       initialReq,
			wantCodes: []codes.Code{codes.InvalidArgument},
		},
		{
			name:      "IDevID Flow Success - Full Process",
			em:        em,
			req:       initialReq,
			id:        idIdevid,
			wantCodes: []codes.Code{codes.OK, codes.OK, codes.OK},
		},
		{
			name:      "TPM 2.0 EK Flow Success - Full Process",
			em:        em,
			tpm:       &mockTPM20Utils{},
			req:       initialReq,
			id:        idTPM20EK,
			wantCodes: []codes.Code{codes.OK, codes.OK, codes.OK},
		},
		{
			name:      "Status Report in New Stream Success - Full Process",
			em:        em,
			req:       statusReq,
			id:        idIdevid,
			wantCodes: []codes.Code{codes.OK, codes.OK},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := New(test.em, test.tpm)
			srv := grpc.NewServer(grpc.Creds(insecure.NewCredentials()))
			bpb.RegisterBootstrapServer(srv, s)
			addr := startTestServer(t, srv)
			conn := createTestClient(t, addr, nil)
			cli := bpb.NewBootstrapClient(conn)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			stream, err := cli.BootstrapStreamV1(ctx)
			if err != nil {
				t.Fatalf("BootstrapStreamV1() failed: %v", err)
			}

			var request *bpb.BootstrapStreamRequestV1
			var response *bpb.BootstrapStreamResponseV1
			for step, wantCode := range test.wantCodes {
				// TODO: Add testing for further steps once handling code is implemented.
				switch step {
				case 0: // Send Bootstrap Request or Report Status Request.
					request = proto.Clone(test.req).(*bpb.BootstrapStreamRequestV1)
				case 1: // Send Challenge Response.
					switch reqType := response.GetChallengeRequest().Type.(type) {
					case *bpb.BootstrapStreamResponseV1_ChallengeRequest_Tpm20Idevid:
						msg := proto.Clone(transportKey).(*bpb.TransportKey)
						msg.Nonce = reqType.Tpm20Idevid.GetNonce()
						serializedMsg, err := proto.Marshal(msg)
						if err != nil {
							t.Fatalf("Failed to serialize transport key message: %v", err)
						}
						digest := sha256.Sum256(serializedMsg)
						sig, err := rsa.SignPKCS1v15(rand.Reader, deviceKey, crypto.SHA256, digest[:])
						if err != nil {
							t.Fatalf("Failed to sign transport key: %v", err)
						}
						request = &bpb.BootstrapStreamRequestV1{
							Type: &bpb.BootstrapStreamRequestV1_ChallengeResponse_{
								ChallengeResponse: &bpb.BootstrapStreamRequestV1_ChallengeResponse{
									Type: &bpb.BootstrapStreamRequestV1_ChallengeResponse_Tpm20Idevid{
										Tpm20Idevid: &bpb.BootstrapStreamRequestV1_ChallengeResponse_ChallengeResponseTPM20IDevID{
											SerializedTransportKey: serializedMsg,
											Signature:              sig,
										},
									},
								},
							},
						}
					case *bpb.BootstrapStreamResponseV1_ChallengeRequest_Tpm20Hmac:
						serializedKey, err := proto.Marshal(transportKey)
						if err != nil {
							t.Fatalf("Failed to serialize transport key message: %v", err)
						}
						digest := sha256.Sum256(serializedKey)
						attest := tpm2.TPMSAttest{
							Magic: tpm2.TPMGeneratedValue,
							Type:  tpm2.TPMSTAttestCertify,
							ExtraData: tpm2.TPM2BData{Buffer: tpm2.Marshal(tpm2.TPMTHA{
								HashAlg: tpm2.TPMAlgSHA256,
								Digest:  digest[:],
							})},
						}
						request = &bpb.BootstrapStreamRequestV1{
							Type: &bpb.BootstrapStreamRequestV1_ChallengeResponse_{
								ChallengeResponse: &bpb.BootstrapStreamRequestV1_ChallengeResponse{
									Type: &bpb.BootstrapStreamRequestV1_ChallengeResponse_Tpm20Hmac{
										Tpm20Hmac: &bpb.BootstrapStreamRequestV1_ChallengeResponse_ChallengeResponseTPM20HMAC{
											SerializedTransportKey: serializedKey,
											Hmac: &epb.HMACChallengeResponse{
												IakPub:                  []byte("IAKPub"),
												IakCertifyInfo:          tpm2.Marshal(tpm2.New2B(attest)),
												IakCertifyInfoSignature: []byte("IAKCertifySignature"),
											},
										},
									},
								},
							},
						}
					case *bpb.BootstrapStreamResponseV1_ChallengeRequest_Tpm12Ek:
					}
				case 2: // Send Report Status Request.
					request = proto.Clone(statusReq).(*bpb.BootstrapStreamRequestV1)
				}

				if test.id != nil {
					switch reqType := request.Type.(type) {
					case *bpb.BootstrapStreamRequestV1_BootstrapRequest:
						reqType.BootstrapRequest.Identity = test.id
					case *bpb.BootstrapStreamRequestV1_ReportStatusRequest:
						reqType.ReportStatusRequest.Identity = test.id
					}
				}
				if err := stream.Send(request); err != nil {
					t.Fatalf("stream.Send(%v) failed: %v", request, err)
				}
				response, err = stream.Recv()
				stat, ok := status.FromError(err)
				if !ok {
					t.Fatalf("failed to extract status code from error: %v", err)
				}

				if stat.Code() != wantCode {
					t.Errorf("[Step %v] stream.Recv() got error code %v, want %v", step, stat.Code(), wantCode)
				}
				if err != nil {
					return
				}

				// TODO: Add checking for further steps once handling code is implemented.
				switch step {
				case 0: // Received Challenge Request.
					if response.GetChallengeRequest() == nil {
						t.Errorf("received nil challenge request")
					}
				case 1: // Received Bootstrap Response or Report Status Response.
					switch resType := response.GetType().(type) {
					case *bpb.BootstrapStreamResponseV1_BootstrapResponse:
						if response.GetBootstrapResponse() == nil {
							t.Errorf("received nil bootstrap data")
						}
						if ov := response.GetBootstrapResponse().GetOwnershipVoucher(); !bytes.Equal(ov, testOV) {
							t.Errorf("unexpected ownership voucher: got %v, want %v", ov, testOV)
						}
						if oc := response.GetBootstrapResponse().GetOwnershipCertificate(); !bytes.Equal(oc, testOC) {
							t.Errorf("unexpected ownership certificate: got %v, want %v", oc, testOC)
						}
						if sig := response.GetBootstrapResponse().GetResponseSignature(); sig != testSig {
							t.Errorf("unexpected response signature: got %v, want %v", sig, testSig)
						}
						recipient, err := hpke.NewRecipient(response.GetBootstrapResponse().GetEncapsulatedKey(), hpkeKey, hpke.HKDFSHA256(), hpke.AES256GCM(), nil)
						if err != nil {
							t.Fatalf("Failed to create HPKE recipient: %v", err)
						}
						plainText, err := recipient.Open(nil, response.GetBootstrapResponse().GetEncryptedSerializedBootstrapData())
						if err != nil {
							t.Fatalf("Failed to decrypt bootstrap data: %v", err)
						}
						gotBootstrapDataSigned := &bpb.BootstrapDataSigned{}
						err = proto.Unmarshal(plainText, gotBootstrapDataSigned)
						if err != nil {
							t.Fatalf("Failed to unmarshal decrypted bootstrap data: %v", err)
						}
						if diff := cmp.Diff(gotBootstrapDataSigned, bootstrapData, protocmp.Transform()); diff != "" {
							t.Errorf("unexpected BootstrapDataSigned, diff = %v", diff)
						}
					case *bpb.BootstrapStreamResponseV1_ReportStatusResponse:
						if response.GetReportStatusResponse() == nil {
							t.Errorf("received nil report status response")
						}
					default:
						t.Errorf("received unexpected response type %T", resType)
					}
				case 2: // Received Report Status Response.
					if response.GetReportStatusResponse() == nil {
						t.Errorf("received nil report status response")
					}
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

func peerAddressContext(t *testing.T, address string) context.Context {
	t.Helper()
	return peer.NewContext(context.Background(), &peer.Peer{
		Addr: &net.TCPAddr{
			IP: net.ParseIP(address),
		},
	})
}

func TestInitializeChassis(t *testing.T) {
	ctx := peerAddressContext(t, "1.1.1.1")
	tests := []struct {
		name    string
		ctx     context.Context
		msg     proto.Message
		want    *types.Chassis
		wantErr bool
	}{
		{
			name: "Successful bootstrap_request",
			ctx:  ctx,
			msg: &bpb.GetBootstrapDataRequest{
				ChassisDescriptor: &bpb.ChassisDescriptor{
					SerialNumber: "1234",
				},
				ControlCardState: &bpb.ControlCardState{
					SerialNumber: "1234",
				},
				Identity: &bpb.Identity{
					Type: &bpb.Identity_IdevidCert{},
				},
			},
			want: &types.Chassis{
				Serials:      []string{"1234"},
				ActiveSerial: "1234",
				IPAddress:    "1.1.1.1",
				Identity:     &bpb.Identity{Type: &bpb.Identity_IdevidCert{}},
			},
		},
		{
			name: "Successful report_status_request",
			ctx:  ctx,
			msg: &bpb.ReportStatusRequest{
				States: []*bpb.ControlCardState{
					{SerialNumber: "1234"},
				},
				Identity: &bpb.Identity{
					Type: &bpb.Identity_EkPpkPub{},
				},
			},
			want: &types.Chassis{
				Serials:      []string{"1234"},
				ActiveSerial: "1234",
				IPAddress:    "1.1.1.1",
				Identity:     &bpb.Identity{Type: &bpb.Identity_EkPpkPub{}},
			},
		},
		{
			name:    "Invalid request",
			ctx:     ctx,
			wantErr: true,
		},
		{
			name:    "No serial number",
			ctx:     ctx,
			msg:     &bpb.GetBootstrapDataRequest{},
			wantErr: true,
		},
		{
			name: "No identity",
			ctx:  ctx,
			msg: &bpb.GetBootstrapDataRequest{
				ControlCardState: &bpb.ControlCardState{
					SerialNumber: "1234",
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
			got, err := initializeChassis(tc.ctx, tc.msg)
			if (err != nil) != tc.wantErr {
				t.Fatalf("initializeChassis err = %v, want nil", err)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(got, tc.want, protocmp.Transform(), cmpopts.IgnoreFields(types.Chassis{}, "ActivePublicKey", "SoftwareImage", "BootConfig", "Authz")); diff != "" {
				t.Errorf("initializeChassis diff = %v", diff)
			}
		})
	}
}
