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

// Package service receives bootstrap requests and responds with the relevant data.
package service

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net"

	log "github.com/golang/glog"
	"github.com/google/go-tpm/tpm2"
	"github.com/openconfig/attestz/service/biz"
	"github.com/openconfig/bootz/common/signature"
	"github.com/openconfig/bootz/common/types"
	"github.com/openconfig/gnmi/errlist"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	epb "github.com/openconfig/attestz/proto/tpm_enrollz"
	bpb "github.com/openconfig/bootz/proto/bootz"
)

// For test overriding purpose.
var TPM20Utils biz.TPM20Utils = &biz.DefaultTPM20Utils{}

// buildEntityLookup constructs an EntityLookup object from a bootstrap request.
func buildEntityLookup(ctx context.Context, req *bpb.GetBootstrapDataRequest) (*types.EntityLookup, error) {
	peerAddr, err := peerAddressFromContext(ctx)
	if err != nil {
		return nil, err
	}
	activeControlCardSerial := req.GetControlCardState().GetSerialNumber()
	if activeControlCardSerial == "" {
		return nil, status.Errorf(codes.InvalidArgument, "no active control card serial provided")
	}
	var partNumber string
	var modular bool
	if len(req.GetChassisDescriptor().GetControlCards()) == 0 {
		modular = false
		partNumber = req.GetChassisDescriptor().GetPartNumber()
	} else {
		modular = true
		for _, card := range req.GetChassisDescriptor().GetControlCards() {
			if card.GetSerialNumber() == activeControlCardSerial {
				partNumber = card.GetPartNumber()
				break
			}
		}
	}
	if partNumber == "" {
		return nil, status.Errorf(codes.InvalidArgument, "active control card with serial %v not found in chassis descriptor", activeControlCardSerial)
	}
	lookup := &types.EntityLookup{
		Manufacturer: req.GetChassisDescriptor().GetManufacturer(),
		SerialNumber: activeControlCardSerial,
		PartNumber:   partNumber,
		IPAddress:    peerAddr,
		Modular:      modular,
	}
	return lookup, nil
}

// EntityManager maintains the entities and their states.
type EntityManager interface {
	ResolveChassis(context.Context, *types.EntityLookup) (*types.Chassis, error)
	GetBootstrapData(context.Context, *types.Chassis, string) (*bpb.BootstrapDataResponse, error)
	SetStatus(context.Context, *bpb.ReportStatusRequest) error
	Sign(context.Context, *bpb.GetBootstrapDataResponse, *types.Chassis, string) error
	ValidateIDevID(context.Context, *x509.Certificate, *types.Chassis) error
}

// Service represents the server and entity manager.
type Service struct {
	bpb.UnimplementedBootstrapServer
	em EntityManager
}

type streamSession struct {
	stream            bpb.Bootstrap_BootstrapStreamServer
	currentState      int
	chassis           *types.Chassis // Store chassis info for later stages
	activeControlCard string
	idevidCert        *x509.Certificate   // For IDevID flow
	nonce             string              // base64 encoded, for TPM 2.0 nonce challenge
	clientNonce       string              // client nonce from bootstrap request
	hmacSensitive     *tpm2.TPMTSensitive // For TPM 2.0 without IDevID
}

func (s *Service) GetBootstrapData(ctx context.Context, req *bpb.GetBootstrapDataRequest) (*bpb.GetBootstrapDataResponse, error) {
	log.Infof("=============================================================================")
	log.Infof("==================== Received request for bootstrap data ====================")
	log.Infof("=============================================================================")
	peerAddr, err := peerAddressFromContext(ctx)
	if err != nil {
		return nil, err
	}
	log.Infof("Received GetBootstrapData request(%+v) from %v", req, peerAddr)
	fixedChassis := true
	chassisDesc := req.GetChassisDescriptor()
	if len(chassisDesc.GetControlCards()) >= 1 {
		fixedChassis = false
	}
	log.Infof("Requesting for %v chassis %v", chassisDesc.GetManufacturer(), chassisDesc.GetSerialNumber())
	lookup := &types.EntityLookup{
		Manufacturer: chassisDesc.GetManufacturer(),
		SerialNumber: chassisDesc.GetSerialNumber(),
		PartNumber:   chassisDesc.GetPartNumber(),
		IPAddress:    peerAddr,
	}
	// Validate the chassis can be serviced
	chassis, err := s.em.ResolveChassis(ctx, lookup)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to resolve chassis to inventory %+v, err: %v", chassisDesc, err)
	}
	log.Infof("Verified server can resolve chassis")

	// If chassis can only be booted into secure mode then return error
	if chassis.BootMode == bpb.BootMode_BOOT_MODE_SECURE && req.GetNonce() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "chassis requires secure boot only")
	}

	// Iterate over the control cards and fetch data for each card.
	var errs errlist.List

	log.Infof("=============================================================================")
	log.Infof("==================== Fetching data for each control card ====================")
	log.Infof("=============================================================================")
	var responses []*bpb.BootstrapDataResponse
	for _, v := range chassisDesc.GetControlCards() {
		bootdata, err := s.em.GetBootstrapData(ctx, chassis, v.GetSerialNumber())
		if err != nil {
			errs.Add(err)
			log.Infof("Error occurred while retrieving data for Serial Number %v", v.SerialNumber)
		}
		responses = append(responses, bootdata)
	}
	if fixedChassis {
		bootdata, err := s.em.GetBootstrapData(ctx, chassis, chassisDesc.GetSerialNumber())
		if err != nil {
			errs.Add(err)
			log.Infof("Error occurred while retrieving data for fixed chassis with serail number %v", lookup.SerialNumber)
		}
		responses = append(responses, bootdata)
	}

	if errs.Err() != nil {
		return nil, errs.Err()
	}
	log.Infof("Successfully fetched data for each control card")
	log.Infof("=============================================================================")

	nonce := req.GetNonce()
	signedResponse := &bpb.BootstrapDataSigned{
		Responses: responses,
		Nonce:     nonce,
	}
	log.Infof("Serializing the response...")
	signedResponseBytes, err := proto.Marshal(signedResponse)
	if err != nil {
		return nil, err
	}
	log.Infof("Successfully serialized the response")

	resp := &bpb.GetBootstrapDataResponse{
		// This field is deprecated but we still include it for backwards compatibility.
		SignedResponse:          signedResponse,
		SerializedBootstrapData: signedResponseBytes,
	}
	log.Infof("Response set")

	// Sign the response if Nonce is provided.
	if nonce != "" {
		log.Infof("=============================================================================")
		log.Infof("====================== Signing the response with nonce ======================")
		log.Infof("=============================================================================")
		if err := s.em.Sign(ctx, resp, chassis, req.GetControlCardState().GetSerialNumber()); err != nil {
			return nil, err
		}
		log.Infof("Signed with nonce")
	}
	log.Infof("Returning response")
	return resp, nil
}

func (s *Service) ReportStatus(ctx context.Context, req *bpb.ReportStatusRequest) (*bpb.EmptyResponse, error) {
	log.Infof("=============================================================================")
	log.Infof("========================== Status report received ===========================")
	log.Infof("=============================================================================")
	peerAddr, err := peerAddressFromContext(ctx)
	if err != nil {
		return nil, err
	}
	log.Infof("Received ReportStatus request(%+v) from %v", req, peerAddr)
	return &bpb.EmptyResponse{}, s.em.SetStatus(ctx, req)
}

const (
	stateInitial = iota
	// TPM 2.0 states
	stateTPM20ChallengeSent
	stateTPM20ReauthChallengeSent
	// Common state
	stateAttested
)

// buildLookupFromReportStatus constructs an EntityLookup object from a ReportStatusRequest.
func buildLookupFromReportStatus(ctx context.Context, req *bpb.ReportStatusRequest) (*types.EntityLookup, error) {
	peerAddr, err := peerAddressFromContext(ctx)
	if err != nil {
		return nil, err
	}
	var ccSerial string
	if states := req.GetStates(); len(states) > 0 {
		ccSerial = states[0].GetSerialNumber()
	}
	if ccSerial == "" {
		return nil, status.Errorf(codes.InvalidArgument, "control card serial is missing in ReportStatusRequest")
	}
	// Note: ReportStatusRequest doesn't have manufacturer or part number. The lookup is simpler.
	lu := &types.EntityLookup{
		SerialNumber: ccSerial,
		IPAddress:    peerAddr,
	}
	return lu, nil
}

// sendIdevidChallenge contains the logic for parsing an IDevID cert, and sending a nonce challenge.
func (s *Service) sendIdevidChallenge(session *streamSession, idevidCertB64 string) error {
	certDER, err := base64.StdEncoding.DecodeString(idevidCertB64)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "failed to decode idevid_cert: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "failed to parse idevid_cert: %v", err)
	}

	if err := s.em.ValidateIDevID(session.stream.Context(), cert, session.chassis); err != nil {
		return status.Errorf(codes.PermissionDenied, "failed to validate idevid_cert: %v", err)
	}
	session.idevidCert = cert
	log.Infof("Successfully parsed IDevID cert for %s", cert.Subject.CommonName)

	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		return status.Errorf(codes.Internal, "failed to generate nonce: %v", err)
	}
	session.nonce = base64.StdEncoding.EncodeToString(nonceBytes)

	challengeResp := &bpb.BootstrapStreamResponse{
		Type: &bpb.BootstrapStreamResponse_Challenge_{
			Challenge: &bpb.BootstrapStreamResponse_Challenge{
				Type: &bpb.BootstrapStreamResponse_Challenge_Nonce{
					Nonce: session.nonce,
				},
			},
		},
	}
	if err := session.stream.Send(challengeResp); err != nil {
		return err
	}
	log.Infof("Sent nonce challenge to IDevID device: %s", session.activeControlCard)
	return nil
}

// sendHMACChallenge contains the logic for sending an HMAC challenge.
func (s *Service) sendHMACChallenge(session *streamSession) error {
	// Generate a restricted HMAC key.
	hmacPub, hmacSensitive, err := TPM20Utils.GenerateRestrictedHMACKey()
	if err != nil {
		return status.Errorf(codes.Internal, "failed to generate restricted HMAC key: %v", err)
	}

	// Wrap HMAC key to EK/PPK public key.
	duplicate, inSymSeed, err := TPM20Utils.WrapHMACKeytoRSAPublicKey(session.chassis.PubKey, hmacPub, hmacSensitive)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to wrap HMAC key to EK/PPK public key: %v", err)
	}

	session.hmacSensitive = hmacSensitive

	challengeResp := &bpb.BootstrapStreamResponse{
		Type: &bpb.BootstrapStreamResponse_Challenge_{
			Challenge: &bpb.BootstrapStreamResponse_Challenge{
				Type: &bpb.BootstrapStreamResponse_Challenge_Tpm20HmacChallenge{
					Tpm20HmacChallenge: &bpb.BootstrapStreamResponse_Challenge_TPM20HMACChallenge{
						Key: session.chassis.PubKeyType,
						HmacChallenge: &epb.HMACChallenge{
							HmacPubKey: tpm2.Marshal(hmacPub),
							Duplicate:  duplicate,
							InSymSeed:  inSymSeed,
						},
					},
				},
			},
		},
	}
	if err := session.stream.Send(challengeResp); err != nil {
		return err
	}
	log.Infof("Sent HMAC challenge to device: %s", session.activeControlCard)
	return nil
}

// establishSessionAndSendChallenge is a helper to establish session and send challenge for TPM2.0 with or without IDevID.
func (s *Service) establishSessionAndSendChallenge(session *streamSession, lookup *types.EntityLookup, identity *bpb.Identity) error {
	if identity == nil {
		return status.Errorf(codes.InvalidArgument, "identity field is missing in request")
	}
	chassis, err := s.em.ResolveChassis(session.stream.Context(), lookup)
	if err != nil {
		return status.Errorf(codes.NotFound, "failed to resolve chassis: %v", err)
	}
	if !chassis.StreamingSupported {
		return status.Errorf(codes.Unimplemented, "streaming bootstrap is not supported for this device")
	}
	session.chassis = chassis
	session.activeControlCard = lookup.SerialNumber
	log.Infof("Resolved device for re-authentication: %s, Chassis: %s", session.activeControlCard, session.chassis.Hostname)

	switch idType := identity.Type.(type) {
	case *bpb.Identity_IdevidCert:
		log.Infof("Starting sendIdevidChallenge for TPM 2.0 with IDevID flow for %s", session.activeControlCard)
		if err := s.sendIdevidChallenge(session, idType.IdevidCert); err != nil {
			return err
		}
		return nil
	case *bpb.Identity_EkPpkPub:
		log.Infof("Starting sendHMACChallenge for TPM 2.0 without IDevID flow for %s", session.activeControlCard)
		if err := s.sendHMACChallenge(session); err != nil {
			return err
		}
		return nil
	default:
		return status.Errorf(codes.InvalidArgument, "unsupported identity type for re-authentication: %T", idType)
	}
}

func (s *Service) BootstrapStream(stream bpb.Bootstrap_BootstrapStreamServer) error {
	ctx := stream.Context()
	session := &streamSession{stream: stream, currentState: stateInitial}

	for {
		in, err := stream.Recv()
		if err == io.EOF {
			log.Infof("Stream closed by client: %s", session.activeControlCard)
			return nil
		}
		if err != nil {
			log.Errorf("Error receiving message: %v", err)
			return err
		}

		switch req := in.Type.(type) {
		case *bpb.BootstrapStreamRequest_BootstrapRequest:
			if session.currentState != stateInitial {
				return status.Errorf(codes.FailedPrecondition, "BootstrapRequest can only be sent as the first message.")
			}
			bootstrapReq := req.BootstrapRequest
			identity := bootstrapReq.GetIdentity()
			session.clientNonce = bootstrapReq.GetNonce()
			log.Infof("Received initial BootstrapRequest: %+v", bootstrapReq)

			if identity == nil {
				return status.Errorf(codes.InvalidArgument, "identity field is missing in BootstrapRequest")
			}

			lu, err := buildEntityLookup(ctx, bootstrapReq)
			if err != nil {
				return status.Errorf(codes.InvalidArgument, "failed to build entity lookup from request: %v", err)
			}

			switch idType := identity.Type.(type) {
			case *bpb.Identity_IdevidCert, *bpb.Identity_EkPpkPub:
				log.Infof("Detected TPM 2.0 flow (ID type: %T)", idType)
				if err := s.establishSessionAndSendChallenge(session, lu, identity); err != nil {
					return err
				}
				session.currentState = stateTPM20ChallengeSent

			case *bpb.Identity_EkPub:
				log.Infof("Detected TPM 1.2 flow (EK only) for %s", session.activeControlCard)
				// TODO: logic to send the ca_pub challenge
				return status.Errorf(codes.Unimplemented, "TPM 1.2 flow not fully implemented")

			default:
				return status.Errorf(codes.InvalidArgument, "unsupported identity type: %T", idType)
			}

		case *bpb.BootstrapStreamRequest_Response_:
			log.Infof("Received Response from %s", session.activeControlCard)
			if session.currentState != stateTPM20ChallengeSent && session.currentState != stateTPM20ReauthChallengeSent {
				return status.Errorf(codes.InvalidArgument, "unexpected state %v for device %s, expecting challenge response", session.currentState, session.activeControlCard)
			}

			challengeResponse := req.Response

			switch challengeType := challengeResponse.Type.(type) {
			case *bpb.BootstrapStreamRequest_Response_NonceSigned:
				if len(session.nonce) == 0 {
					return status.Errorf(codes.InvalidArgument, "received unexpected nonce challenge response")
				}
				// Base64-encode the raw signed nonce before passing it to the Verify function.
				signedNonceB64 := base64.StdEncoding.EncodeToString(challengeResponse.GetNonceSigned())
				// The device signs the base64-encoded nonce string.
				if err := signature.Verify(session.idevidCert, []byte(session.nonce), signedNonceB64); err != nil {
					log.Errorf("Nonce signature verification failed for device %s. Signature: %s, Error: %v", session.activeControlCard, signedNonceB64, err)
					return status.Errorf(codes.InvalidArgument, "nonce signature verification failed: %v", err)
				}
				log.Infof("Nonce signature verified successfully for %s", session.activeControlCard)

			case *bpb.BootstrapStreamRequest_Response_HmacChallengeResponse:
				if session.hmacSensitive == nil {
					return status.Errorf(codes.InvalidArgument, "received unexpected HMAC challenge response")
				}
				hmacResponse := challengeResponse.GetHmacChallengeResponse()

				// Verify HMAC Challenge response.
				if err = TPM20Utils.VerifyHMAC(hmacResponse.GetIakCertifyInfo(), hmacResponse.GetIakCertifyInfoSignature(), session.hmacSensitive); err != nil {
					return status.Errorf(codes.InvalidArgument, "HMAC verification failed: %v", err)
				}
				// Verify IAK public key attributes.
				iakPubKey, err := TPM20Utils.VerifyIAKAttributes(hmacResponse.GetIakPub())
				if err != nil {
					return status.Errorf(codes.InvalidArgument, "IAK public key verification failed: %v", err)
				}
				iakCertifyInfo, err := tpm2.Unmarshal[tpm2.TPMSAttest](hmacResponse.GetIakCertifyInfo())
				if err != nil {
					return status.Errorf(codes.InvalidArgument, "IAK certify info unmarshaling failed: %v", err)
				}
				// Verify IAK certify info.
				if err := TPM20Utils.VerifyCertifyInfo(iakCertifyInfo, iakPubKey); err != nil {
					return status.Errorf(codes.InvalidArgument, "IAK certify info verification failed: %v", err)
				}
				log.Infof("HMAC challenge verified successfully for %s", session.activeControlCard)

			case *bpb.BootstrapStreamRequest_Response_Nonce:
				log.Infof("received TPM 1.2 nonce challenge response for %s", session.activeControlCard)
				// TODO: logic to verify the nonce challenge
				return status.Errorf(codes.Unimplemented, "TPM 1.2 flow not fully implemented")

			default:
				return status.Errorf(codes.InvalidArgument, "unsupported challenge response type: %T", challengeType)
			}

			if session.currentState == stateTPM20ReauthChallengeSent {
				log.Infof("Acknowledging status report for %s after re-authentication", session.activeControlCard)
				resp := &bpb.BootstrapStreamResponse{
					Type: &bpb.BootstrapStreamResponse_ReportStatusResponse{
						ReportStatusResponse: &bpb.EmptyResponse{},
					},
				}
				if err := session.stream.Send(resp); err != nil {
					return err
				}
				log.Infof("Acknowledged status report from %s", session.activeControlCard)
				session.currentState = stateAttested
				continue
			}

			// If verification is successful, fetch and send the bootstrap data.
			log.Infof("Fetching bootstrap data for %s", session.activeControlCard)
			bootdata, err := s.em.GetBootstrapData(ctx, session.chassis, session.activeControlCard)
			if err != nil {
				return status.Errorf(codes.Internal, "failed to get bootstrap data: %v", err)
			}
			serializedSignedData, err := proto.Marshal(&bpb.BootstrapDataSigned{
				Responses: []*bpb.BootstrapDataResponse{bootdata},
				Nonce:     session.clientNonce,
			})
			if err != nil {
				return status.Errorf(codes.Internal, "failed to serialize bootstrap data: %v", err)
			}
			bootstrapRespForSigning := &bpb.GetBootstrapDataResponse{
				SerializedBootstrapData: serializedSignedData,
			}
			if err := s.em.Sign(ctx, bootstrapRespForSigning, session.chassis, session.activeControlCard); err != nil {
				return status.Errorf(codes.Internal, "failed to sign bootstrap data: %v", err)
			}

			// Send the bootstrap data to the device.
			finalStreamResp := &bpb.BootstrapStreamResponse{
				Type: &bpb.BootstrapStreamResponse_BootstrapResponse{
					BootstrapResponse: bootstrapRespForSigning,
				},
			}
			if err := session.stream.Send(finalStreamResp); err != nil {
				return err
			}
			log.Infof("Successfully sent bootstrap data to %s", session.activeControlCard)
			session.currentState = stateAttested

		case *bpb.BootstrapStreamRequest_ReportStatusRequest:
			log.Infof("=============================================================================")
			log.Infof("====================== Stream status report received ======================")
			log.Infof("=============================================================================")
			log.Infof("Received ReportStatusRequest from %s: %+v", session.activeControlCard, req.ReportStatusRequest)

			if session.currentState == stateInitial {
				log.Info("Received ReportStatusRequest on a new stream. Starting re-authentication...")
				lu, err := buildLookupFromReportStatus(ctx, req.ReportStatusRequest)
				if err != nil {
					return err
				}

				if err := s.establishSessionAndSendChallenge(session, lu, req.ReportStatusRequest.GetIdentity()); err != nil {
					return err
				}

				session.currentState = stateTPM20ReauthChallengeSent
			} else {
				if err := s.em.SetStatus(ctx, req.ReportStatusRequest); err != nil {
					log.Errorf("Failed to set status for device %s: %v", session.activeControlCard, err)
					return status.Errorf(codes.Internal, "failed to set status: %v", err)
				}
				log.Infof("Successfully set status for device %s", session.activeControlCard)

				resp := &bpb.BootstrapStreamResponse{
					Type: &bpb.BootstrapStreamResponse_ReportStatusResponse{
						ReportStatusResponse: &bpb.EmptyResponse{},
					},
				}
				if err := stream.Send(resp); err != nil {
					return err
				}
				log.Infof("Acknowledged status report from %s", session.activeControlCard)
			}
		default:
			return status.Errorf(codes.InvalidArgument, "unexpected message type: %T", req)
		}
	}
}

// SetDeviceConfiguration is a public API for allowing the device configuration to be set for each device the
// will be responsible for configuring.  This will be only available for testing.
func (s *Service) SetDeviceConfiguration(ctx context.Context) error {
	return status.Errorf(codes.Unimplemented, "Unimplemented")
}

func peerAddressFromContext(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", status.Error(codes.InvalidArgument, "no peer information found in request context")
	}
	a, ok := p.Addr.(*net.TCPAddr)
	if !ok {
		return "", status.Errorf(codes.InvalidArgument, "peer address type must be TCP")
	}
	return a.IP.String(), nil
}

// New creates a new service.
func New(em EntityManager) *Service {
	return &Service{
		em: em,
	}
}
