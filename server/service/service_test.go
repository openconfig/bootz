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
	"crypto/hmac"
	"crypto/hpke"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-tpm/tpm2"
	"github.com/openconfig/attestz/service/biz"
	ownercertificate "github.com/openconfig/bootz/common/owner_certificate"
	ownershipvoucher "github.com/openconfig/bootz/common/ownership_voucher"
	"github.com/openconfig/bootz/common/signature"
	"github.com/openconfig/bootz/common/types"
	"go.mozilla.org/pkcs7"
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
	testNonce         = "test-client-nonce"
	testSerial        = "test-serial-123"
	testIPAddress     = "1.2.3.4"
	testPublicKeyType = epb.Key_KEY_EK
	testAIKPubDigest  = []byte("test-aik-pub-digest0") // Must be 20 bytes.
	testChassis       = &types.Chassis{StreamingSupported: true}
	testBootstrapData = &bpb.BootstrapDataResponse{BootConfig: &bpb.BootConfig{VendorConfig: []byte("test-vendor-config")}}
)

// mockArtifactManager is for testing purposes.
type mockArtifactManager struct {
	oc       *x509.Certificate
	ocKey    crypto.PrivateKey
	vendorCA *x509.Certificate
	ov       []byte
	pub      crypto.PublicKey
}

func (m *mockArtifactManager) BootzServerTrustAnchorKeyPair() (*x509.Certificate, crypto.PrivateKey) {
	return &x509.Certificate{}, nil
}

func (m *mockArtifactManager) OwnerCertificateKeyPair() (*x509.Certificate, crypto.PrivateKey) {
	return m.oc, m.ocKey
}

func (m *mockArtifactManager) OwnershipVoucher(ctx context.Context, serial string, vendor string) ([]byte, error) {
	return m.ov, nil
}

func (m *mockArtifactManager) PublicKey(ctx context.Context, serial string, vendor string) (crypto.PublicKey, epb.Key, error) {
	return m.pub, testPublicKeyType, nil
}

func (m *mockArtifactManager) VendorCABundle() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(m.vendorCA)
	return pool
}

// mockChassisManager is for testing purposes.
type mockChassisManager struct {
	chassis          *types.Chassis
	chassisErr       error
	bootstrapData    *bpb.BootstrapDataResponse
	bootstrapDataErr error
}

func (m *mockChassisManager) ResolveChassis(ctx context.Context, chassis *types.Chassis) error {
	chassisCopy := *chassis
	*chassis = *m.chassis
	chassis.Serials = chassisCopy.Serials
	chassis.ActiveSerial = chassisCopy.ActiveSerial
	chassis.IPAddress = chassisCopy.IPAddress
	chassis.Identity = chassisCopy.Identity
	return m.chassisErr
}
func (m *mockChassisManager) GenerateBootstrapData(context.Context, *types.Chassis, string) (*bpb.BootstrapDataResponse, error) {
	return m.bootstrapData, m.bootstrapDataErr
}
func (m *mockChassisManager) UpdateStatus(context.Context, *bpb.ReportStatusRequest) error {
	return nil
}

// mockTPM20Utils is for testing purposes.
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
	// For testing, we use OC as PDC.
	deviceOC, deviceOCKey, err := ownercertificate.NewRSACertificate("Owner Certificate", "", nil, nil)
	if err != nil {
		t.Fatalf("Failed to create owner certificate: %v", err)
	}
	vendorCA, vendorCAKey, err := ownercertificate.NewRSACertificate("Vendor CA", "", nil, nil)
	if err != nil {
		t.Fatalf("Failed to create vendor certificate authority: %v", err)
	}
	deviceOV, err := ownershipvoucher.NewOwnershipVoucher("json", testSerial, deviceOC, vendorCA, vendorCAKey)
	if err != nil {
		t.Fatalf("Failed to create ownership voucher: %v", err)
	}
	deviceCert, deviceKey, err := ownercertificate.NewRSACertificate("test-device", testSerial, vendorCA, vendorCAKey)
	if err != nil {
		t.Fatalf("Failed to create IDevID certificate: %v", err)
	}
	idevid := base64.StdEncoding.EncodeToString(deviceCert.Raw)
	ekPub := &rsa.PublicKey{N: big.NewInt(123456789), E: 65537}
	am := &mockArtifactManager{
		oc:       deviceOC,
		ocKey:    deviceOCKey,
		vendorCA: vendorCA,
		ov:       deviceOV,
		pub:      ekPub,
	}
	cm := &mockChassisManager{
		chassis:       testChassis,
		bootstrapData: testBootstrapData,
	}
	initialReq := &bpb.BootstrapStreamRequest{
		Type: &bpb.BootstrapStreamRequest_BootstrapRequest{
			BootstrapRequest: &bpb.GetBootstrapDataRequest{
				ChassisDescriptor: &bpb.ChassisDescriptor{SerialNumber: testSerial},
				ControlCardState:  &bpb.ControlCardState{SerialNumber: testSerial},
			},
		},
	}
	statusReq := &bpb.BootstrapStreamRequest{
		Type: &bpb.BootstrapStreamRequest_ReportStatusRequest{
			ReportStatusRequest: &bpb.ReportStatusRequest{
				States: []*bpb.ControlCardState{
					{SerialNumber: testSerial},
				},
			},
		},
	}
	idIdevid := &bpb.Identity{Type: &bpb.Identity_IdevidCert{IdevidCert: idevid}}
	idNoIdevid := &bpb.Identity{Type: &bpb.Identity_EkPpkPub{EkPpkPub: true}}

	tests := []struct {
		name         string
		req          *bpb.BootstrapStreamRequest
		id           *bpb.Identity
		wantErrCode  codes.Code
		signedNonce  []byte
		reportStatus bool
	}{
		{
			name:        "Missing Identity - Invalid Argument",
			req:         initialReq,
			wantErrCode: codes.InvalidArgument,
		},
		{
			name: "IDevID Flow Success - Full End-to-End",
			req:  initialReq,
			id:   idIdevid,
		},
		{
			name: "IDevID Flow Re-authentication on new stream with Status Report",
			req:  statusReq,
			id:   idIdevid,
		},
		{
			name: "TPM 2.0 no-IDevID Flow Success - Full End-to-End",
			req:  initialReq,
			id:   idNoIdevid,
		},
		{
			name: "TPM 2.0 no-IDevID Re-authentication on new stream with Status Report",
			req:  statusReq,
			id:   idNoIdevid,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s, err := New(am, cm, &mockTPM20Utils{})
			if err != nil {
				t.Fatalf("New() failed: %v", err)
			}
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

				// === Second Send: Respond with Signed Nonce ===
				finalSignedNonce, err := signature.Sign(deviceKey, deviceCert.SignatureAlgorithm, []byte(nonce))
				if err != nil {
					t.Fatalf("Failed to sign nonce: %v", err)
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
				if hmac.GetKey() != testPublicKeyType {
					t.Errorf("Unexpected key type in challenge: got %v, want %v", hmac.GetKey(), testPublicKeyType)
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
			if err != nil {
				t.Fatalf("stream.Recv() for final response got unexpected error: %v", err)
			}

			// Handle re-authentication flow initiated by a status report.
			if _, ok := test.req.Type.(*bpb.BootstrapStreamRequest_ReportStatusRequest); ok {
				if finalResp.GetReportStatusResponse() == nil {
					t.Fatalf("Expected report status response for re-auth, but got: %v", finalResp)
				}
				return // End of test for this case.
			}

			bootstrapWrapper := finalResp.GetBootstrapResponse()
			if bootstrapWrapper == nil {
				t.Fatalf("Expected bootstrap response, but got: %v", finalResp)
			}
			if bootstrapWrapper.GetSerializedBootstrapData() == nil {
				t.Error("Final response is missing the serialized bootstrap data")
			}

			// === Third Stage: Status Reporting ===
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
			if err != nil {
				t.Fatalf("Got unexpected error on status report: %v", err)
			}
			if ack.GetReportStatusResponse() == nil {
				t.Fatalf("Expected ReportStatusResponse, got %T", ack.Type)
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
	// For testing, we use OC as PDC.
	deviceOC, deviceOCKey, err := ownercertificate.NewRSACertificate("Owner Certificate", "", nil, nil)
	if err != nil {
		t.Fatalf("Failed to create owner certificate: %v", err)
	}
	vendorCA, vendorCAKey, err := ownercertificate.NewRSACertificate("Vendor CA", "", nil, nil)
	if err != nil {
		t.Fatalf("Failed to create vendor certificate authority: %v", err)
	}
	deviceOV, err := ownershipvoucher.NewOwnershipVoucher("json", testSerial, deviceOC, vendorCA, vendorCAKey)
	if err != nil {
		t.Fatalf("Failed to create ownership voucher: %v", err)
	}
	deviceCert, deviceKey, err := ownercertificate.NewRSACertificate("test-device", testSerial, vendorCA, vendorCAKey)
	if err != nil {
		t.Fatalf("Failed to create IDevID certificate: %v", err)
	}
	idevid := base64.StdEncoding.EncodeToString(deviceCert.Raw)
	ek, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	idIdevid := &bpb.Identity{Type: &bpb.Identity_IdevidCert{IdevidCert: idevid}}
	idTPM20EK := &bpb.Identity{Type: &bpb.Identity_Tpm20EkPub{Tpm20EkPub: []byte{}}}
	idTPM12EK := &bpb.Identity{Type: &bpb.Identity_Tpm12EkPub{Tpm12EkPub: []byte{}}}
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
	am := &mockArtifactManager{
		oc:       deviceOC,
		ocKey:    deviceOCKey,
		vendorCA: vendorCA,
		ov:       deviceOV,
		pub:      &ek.PublicKey,
	}
	cm := &mockChassisManager{
		chassis:       testChassis,
		bootstrapData: testBootstrapData,
	}
	initialReq := &bpb.BootstrapStreamRequestV1{
		Type: &bpb.BootstrapStreamRequestV1_BootstrapRequest{
			BootstrapRequest: &bpb.GetBootstrapDataRequest{
				ChassisDescriptor: &bpb.ChassisDescriptor{SerialNumber: testSerial},
				ControlCardState:  &bpb.ControlCardState{SerialNumber: testSerial},
				Nonce:             testNonce,
				AikPubDigest:      testAIKPubDigest,
			},
		},
	}
	statusReq := &bpb.BootstrapStreamRequestV1{
		Type: &bpb.BootstrapStreamRequestV1_ReportStatusRequest{
			ReportStatusRequest: &bpb.ReportStatusRequest{
				States: []*bpb.ControlCardState{
					{SerialNumber: testSerial},
				},
				AikPubDigest: testAIKPubDigest,
			},
		},
	}

	tests := []struct {
		name      string
		req       *bpb.BootstrapStreamRequestV1
		id        *bpb.Identity
		wantCodes []codes.Code
	}{
		{
			name:      "Missing Identity - Invalid Argument",
			req:       initialReq,
			wantCodes: []codes.Code{codes.InvalidArgument},
		},
		{
			name:      "IDevID Flow Success - Full Process",
			req:       initialReq,
			id:        idIdevid,
			wantCodes: []codes.Code{codes.OK, codes.OK, codes.OK},
		},
		{
			name:      "TPM 2.0 EK Flow Success - Full Process",
			req:       initialReq,
			id:        idTPM20EK,
			wantCodes: []codes.Code{codes.OK, codes.OK, codes.OK},
		},
		{
			name:      "TPM 1.2 EK Flow Success - Full Process",
			req:       initialReq,
			id:        idTPM12EK,
			wantCodes: []codes.Code{codes.OK, codes.OK, codes.OK},
		},
		{
			name:      "Status Report in New Stream Success - Full Process",
			req:       statusReq,
			id:        idIdevid,
			wantCodes: []codes.Code{codes.OK, codes.OK},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s, err := New(am, cm, &mockTPM20Utils{})
			if err != nil {
				t.Fatalf("New() failed: %v", err)
			}
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
						sig, err := signature.Sign(deviceKey, deviceCert.SignatureAlgorithm, serializedMsg)
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
						blob, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, ek, reqType.Tpm12Ek.GetBlobEncrypted(), []byte("TCPA"))
						if err != nil {
							t.Fatalf("Failed to decrypt TPM 1.2 EK challenge blob: %v", err)
						}
						var asym TPMAsymCAContents
						_, err = binary.Decode(blob, binary.BigEndian, &asym)
						if err != nil {
							t.Fatalf("Failed to decode TPM 1.2 EK challenge blob: %v", err)
						}
						if !bytes.Equal(asym.IDDigest[:], testAIKPubDigest) {
							t.Errorf("unexpected AIK public digest: got %v, want %v", asym.IDDigest, testAIKPubDigest)
						}
						serializedKey, err := proto.Marshal(transportKey)
						if err != nil {
							t.Fatalf("Failed to serialize transport key message: %v", err)
						}
						mac := hmac.New(sha256.New, asym.Key[:])
						mac.Write(serializedKey)
						request = &bpb.BootstrapStreamRequestV1{
							Type: &bpb.BootstrapStreamRequestV1_ChallengeResponse_{
								ChallengeResponse: &bpb.BootstrapStreamRequestV1_ChallengeResponse{
									Type: &bpb.BootstrapStreamRequestV1_ChallengeResponse_Tpm12Ek{
										Tpm12Ek: &bpb.BootstrapStreamRequestV1_ChallengeResponse_ChallengeResponseTPM12EK{
											SerializedTransportKey: serializedKey,
											Hash:                   mac.Sum(nil),
										},
									},
								},
							},
						}
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
						if ov := response.GetBootstrapResponse().GetOwnershipVoucher(); !bytes.Equal(ov, deviceOV) {
							t.Errorf("unexpected ownership voucher: got %x, want %x", ov, deviceOV)
						}
						oc := response.GetBootstrapResponse().GetOwnershipCertificate()
						p7, err := pkcs7.Parse(oc)
						if err != nil {
							t.Errorf("failed to parse PKCS7 data: %x", oc)
						}
						if !bytes.Equal(p7.Certificates[0].Raw, deviceOC.Raw) {
							t.Errorf("unexpected owner certificate: got %x, want %x", p7.Certificates[0].Raw, deviceOC.Raw)
						}
						var ocKey crypto.PrivateKey = deviceOCKey
						signer, ok := ocKey.(crypto.Signer)
						if !ok {
							t.Fatalf("private key does not implement crypto.Signer")
						}
						hash := sha256.Sum256(response.GetBootstrapResponse().EncryptedSerializedBootstrapData)
						wantSig, err := signer.Sign(rand.Reader, hash[:], crypto.SHA256)
						if err != nil {
							t.Fatalf("Failed to call signer.Sign(): %v", err)
						}
						wantSigString := base64.StdEncoding.EncodeToString(wantSig)
						if sig := response.GetBootstrapResponse().GetResponseSignature(); sig != wantSigString {
							t.Errorf("unexpected response signature: got %v, want %v", sig, wantSigString)
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
	ctx := peerAddressContext(t, testIPAddress)
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
					SerialNumber: testSerial,
				},
				ControlCardState: &bpb.ControlCardState{
					SerialNumber: testSerial,
				},
				Identity: &bpb.Identity{
					Type: &bpb.Identity_IdevidCert{},
				},
			},
			want: &types.Chassis{
				Serials:      []string{testSerial},
				ActiveSerial: testSerial,
				IPAddress:    testIPAddress,
				Identity:     &bpb.Identity{Type: &bpb.Identity_IdevidCert{}},
			},
		},
		{
			name: "Successful report_status_request",
			ctx:  ctx,
			msg: &bpb.ReportStatusRequest{
				States: []*bpb.ControlCardState{
					{SerialNumber: testSerial},
				},
				Identity: &bpb.Identity{
					Type: &bpb.Identity_EkPpkPub{},
				},
			},
			want: &types.Chassis{
				Serials:      []string{testSerial},
				ActiveSerial: testSerial,
				IPAddress:    testIPAddress,
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
					SerialNumber: testSerial,
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
			if diff := cmp.Diff(got, tc.want, protocmp.Transform()); diff != "" {
				t.Errorf("initializeChassis diff = %v", diff)
			}
		})
	}
}
