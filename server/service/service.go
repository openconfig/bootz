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
	"encoding/pem"
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

const (
	stateInitial = iota
	// TPM 2.0 states
	stateTPM20ChallengeSent
	stateTPM20ReauthChallengeSent
	// Common state
	stateAttested
)

// EntityManager maintains the entities and their states.
type EntityManager interface {
	ResolveChassis(context.Context, *types.EntityLookup) (*types.Chassis, error)
	GetBootstrapData(context.Context, *types.Chassis, string) (*bpb.BootstrapDataResponse, error)
	SetStatus(context.Context, *bpb.ReportStatusRequest) error
	Sign(context.Context, *bpb.GetBootstrapDataResponse, *types.Chassis) error
	ValidateIDevID(context.Context, *x509.Certificate, []byte, *types.Chassis) error
}

// Service represents the server and entity manager.
type Service struct {
	bpb.UnimplementedBootstrapServer
	em    EntityManager
	tpm20 biz.TPM20Utils
}

type streamSession struct {
	stream        bpb.Bootstrap_BootstrapStreamServer
	currentState  int
	chassis       *types.Chassis           // Store chassis info for later stages
	status        *bpb.ReportStatusRequest // Store status for later stages
	clientNonce   string                   // client nonce from bootstrap request
	idevidCert    *x509.Certificate        // For IDevID flow
	nonce         string                   // base64 encoded, for TPM 2.0 nonce challenge
	hmacSensitive *tpm2.TPMTSensitive      // For TPM 2.0 without IDevID HMAC challenge
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
	var serials []string
	chassisDesc := req.GetChassisDescriptor()
	if len(chassisDesc.GetControlCards()) > 0 { // Modular chassis
		for _, v := range chassisDesc.GetControlCards() {
			serials = append(serials, v.GetSerialNumber())
		}
	} else { // Fixed form factor chassis
		serials = append(serials, chassisDesc.GetSerialNumber())
	}
	log.Infof("Requesting for %v chassis %v", chassisDesc.GetManufacturer(), chassisDesc.GetSerialNumber())
	lookup := &types.EntityLookup{
		Serials:      serials,
		ActiveSerial: req.GetControlCardState().GetSerialNumber(),
		Manufacturer: chassisDesc.GetManufacturer(),
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
	for _, v := range serials {
		bootdata, err := s.em.GetBootstrapData(ctx, chassis, v)
		if err != nil {
			errs.Add(err)
			log.Infof("Error occurred while retrieving data for serial number %v", v)
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
		if err := s.em.Sign(ctx, resp, chassis); err != nil {
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

func (s *Service) BootstrapStream(stream bpb.Bootstrap_BootstrapStreamServer) error {
	ctx := stream.Context()
	session := &streamSession{stream: stream, currentState: stateInitial, chassis: &types.Chassis{}}

	for {
		in, err := stream.Recv()
		if err == io.EOF {
			log.Infof("Stream closed by client: %s", session.chassis.ActiveSerial)
			return nil
		}
		if err != nil {
			log.Errorf("Error receiving message: %v", err)
			return err
		}

		switch req := in.GetType().(type) {
		case *bpb.BootstrapStreamRequest_BootstrapRequest:
			if session.currentState != stateInitial {
				return status.Errorf(codes.FailedPrecondition, "BootstrapRequest can only be sent as the first message.")
			}
			bootstrapReq := req.BootstrapRequest
			session.clientNonce = bootstrapReq.GetNonce()
			log.Infof("Received initial BootstrapRequest: %+v", bootstrapReq)

			lu, err := buildEntityLookup(ctx, in)
			if err != nil {
				return status.Errorf(codes.InvalidArgument, "failed to build entity lookup from request: %v", err)
			}

			switch idType := lu.Identity.GetType().(type) {
			case *bpb.Identity_IdevidCert, *bpb.Identity_EkPpkPub:
				log.Infof("Detected TPM 2.0 flow (ID type: %T) for device %s", idType, lu.ActiveSerial)
				if err := s.establishSessionAndSendChallenge(session, lu); err != nil {
					return err
				}
				session.currentState = stateTPM20ChallengeSent

			case *bpb.Identity_EkPub:
				log.Infof("Detected TPM 1.2 flow (EK only) for device %s", lu.ActiveSerial)
				// TODO: logic to send the ca_pub challenge
				return status.Errorf(codes.Unimplemented, "TPM 1.2 flow not fully implemented")

			default:
				return status.Errorf(codes.InvalidArgument, "unsupported identity type: %T", idType)
			}

		case *bpb.BootstrapStreamRequest_Response_:
			if session.currentState != stateTPM20ChallengeSent && session.currentState != stateTPM20ReauthChallengeSent {
				return status.Errorf(codes.InvalidArgument, "unexpected challenge response")
			}
			log.Infof("Received Response from device %s", session.chassis.ActiveSerial)
			challengeResponse := req.Response

			switch challengeType := challengeResponse.GetType().(type) {
			case *bpb.BootstrapStreamRequest_Response_NonceSigned:
				if len(session.nonce) == 0 {
					return status.Errorf(codes.InvalidArgument, "received unexpected nonce challenge response")
				}
				// Base64-encode the raw signed nonce before passing it to the Verify function.
				signedNonceB64 := base64.StdEncoding.EncodeToString(challengeResponse.GetNonceSigned())
				// The device signs the base64-encoded nonce string.
				if err := signature.Verify(session.idevidCert, []byte(session.nonce), signedNonceB64); err != nil {
					log.Errorf("Nonce signature verification failed for device %s. Signature: %s, Error: %v", session.chassis.ActiveSerial, signedNonceB64, err)
					return status.Errorf(codes.InvalidArgument, "nonce signature verification failed: %v", err)
				}
				log.Infof("Nonce signature verified successfully for device %s", session.chassis.ActiveSerial)

			case *bpb.BootstrapStreamRequest_Response_HmacChallengeResponse:
				if session.hmacSensitive == nil {
					return status.Errorf(codes.InvalidArgument, "received unexpected HMAC challenge response")
				}
				hmacResponse := challengeResponse.GetHmacChallengeResponse()

				// Verify HMAC Challenge response.
				if err = s.tpm20.VerifyHMAC(hmacResponse.GetIakCertifyInfo(), hmacResponse.GetIakCertifyInfoSignature(), session.hmacSensitive); err != nil {
					return status.Errorf(codes.InvalidArgument, "HMAC verification failed: %v", err)
				}
				// Verify IAK public key attributes.
				iakPubKey, err := s.tpm20.VerifyIAKAttributes(hmacResponse.GetIakPub())
				if err != nil {
					return status.Errorf(codes.InvalidArgument, "IAK public key verification failed: %v", err)
				}
				iakCertifyInfo, err := tpm2.Unmarshal[tpm2.TPMSAttest](hmacResponse.GetIakCertifyInfo())
				if err != nil {
					return status.Errorf(codes.InvalidArgument, "IAK certify info unmarshaling failed: %v", err)
				}
				// Verify IAK certify info.
				if err := s.tpm20.VerifyCertifyInfo(iakCertifyInfo, iakPubKey); err != nil {
					return status.Errorf(codes.InvalidArgument, "IAK certify info verification failed: %v", err)
				}
				log.Infof("HMAC challenge verified successfully for device %s", session.chassis.ActiveSerial)

			case *bpb.BootstrapStreamRequest_Response_Nonce:
				log.Infof("received TPM 1.2 nonce challenge response for %s", session.chassis.ActiveSerial)
				// TODO: logic to verify the nonce challenge
				return status.Errorf(codes.Unimplemented, "TPM 1.2 flow not fully implemented")

			default:
				return status.Errorf(codes.InvalidArgument, "unsupported challenge response type: %T", challengeType)
			}

			if session.currentState == stateTPM20ReauthChallengeSent {
				log.Infof("Acknowledging status report after re-authentication for device %s", session.chassis.ActiveSerial)
				if err := s.updateStatusAndSendAcknowledgement(session); err != nil {
					return err
				}

				session.currentState = stateAttested
				continue
			}

			// If verification is successful, fetch and send the bootstrap data.
			var responses []*bpb.BootstrapDataResponse
			for _, v := range session.chassis.Serials {
				log.Infof("Fetching bootstrap data for serial number %s", v)
				bootdata, err := s.em.GetBootstrapData(ctx, session.chassis, v)
				if err != nil {
					return status.Errorf(codes.Internal, "failed to get bootstrap data for serial number %s: %v", v, err)
				}
				responses = append(responses, bootdata)
			}
			serializedSignedData, err := proto.Marshal(&bpb.BootstrapDataSigned{
				Responses: responses,
				Nonce:     session.clientNonce,
			})
			if err != nil {
				return status.Errorf(codes.Internal, "failed to serialize bootstrap data: %v", err)
			}
			bootstrapRespForSigning := &bpb.GetBootstrapDataResponse{
				SerializedBootstrapData: serializedSignedData,
			}
			if err := s.em.Sign(ctx, bootstrapRespForSigning, session.chassis); err != nil {
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
			log.Infof("Successfully sent bootstrap data to device %s", session.chassis.ActiveSerial)
			session.currentState = stateAttested

		case *bpb.BootstrapStreamRequest_ReportStatusRequest:
			log.Infof("=============================================================================")
			log.Infof("====================== Stream status report received ======================")
			log.Infof("=============================================================================")
			log.Infof("Received ReportStatusRequest from %s: %+v", session.chassis.ActiveSerial, req.ReportStatusRequest)
			session.status = req.ReportStatusRequest

			if session.currentState == stateInitial {
				log.Info("Received ReportStatusRequest on a new stream. Starting re-authentication...")
				lu, err := buildEntityLookup(ctx, in)
				if err != nil {
					return err
				}

				if err := s.establishSessionAndSendChallenge(session, lu); err != nil {
					return err
				}

				session.currentState = stateTPM20ReauthChallengeSent
				continue
			}

			if err := s.updateStatusAndSendAcknowledgement(session); err != nil {
				return err
			}

		default:
			return status.Errorf(codes.InvalidArgument, "unexpected message type: %T", req)
		}
	}
}

// sendIdevidChallenge contains the logic for parsing an IDevID cert, and sending a nonce challenge.
func (s *Service) sendIdevidChallenge(session *streamSession, idevidCertB64 string) error {
	var certDER, intermediates []byte
	var pemBlock *pem.Block
	var err error
	certDER, err = base64.StdEncoding.DecodeString(idevidCertB64)
	if err != nil {
		// If we can't base64 decode the cert, it might be a PEM-encoded string.
		// Find the first (leaf) cert in the PEM block, then decode it to a DER string.
		pemBlock, intermediates = pem.Decode([]byte(idevidCertB64))
		if pemBlock == nil {
			return status.Errorf(codes.InvalidArgument, "idevid_cert is not a valid PEM block or base64 string: %v", idevidCertB64)
		}
		certDER = pemBlock.Bytes
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "failed to parse idevid_cert: %v", err)
	}

	if err := s.em.ValidateIDevID(session.stream.Context(), cert, intermediates, session.chassis); err != nil {
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
	log.Infof("Sent nonce challenge to IDevID device %s", session.chassis.ActiveSerial)
	return nil
}

// sendHMACChallenge contains the logic for sending an HMAC challenge.
func (s *Service) sendHMACChallenge(session *streamSession) error {
	// Generate a restricted HMAC key.
	hmacPub, hmacSensitive, err := s.tpm20.GenerateRestrictedHMACKey()
	if err != nil {
		return status.Errorf(codes.Internal, "failed to generate restricted HMAC key: %v", err)
	}

	// Wrap HMAC key to EK/PPK public key.
	duplicate, inSymSeed, err := s.tpm20.WrapHMACKeytoRSAPublicKey(session.chassis.ActivePublicKey, hmacPub, hmacSensitive)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to wrap HMAC key to EK/PPK public key: %v", err)
	}

	session.hmacSensitive = hmacSensitive

	challengeResp := &bpb.BootstrapStreamResponse{
		Type: &bpb.BootstrapStreamResponse_Challenge_{
			Challenge: &bpb.BootstrapStreamResponse_Challenge{
				Type: &bpb.BootstrapStreamResponse_Challenge_Tpm20HmacChallenge{
					Tpm20HmacChallenge: &bpb.BootstrapStreamResponse_Challenge_TPM20HMACChallenge{
						Key: session.chassis.ActivePublicKeyType,
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
	log.Infof("Sent HMAC challenge to device %s", session.chassis.ActiveSerial)
	return nil
}

// establishSessionAndSendChallenge is a helper to establish session and send challenge for TPM2.0 with or without IDevID.
func (s *Service) establishSessionAndSendChallenge(session *streamSession, lookup *types.EntityLookup) error {
	chassis, err := s.em.ResolveChassis(session.stream.Context(), lookup)
	if err != nil {
		return status.Errorf(codes.NotFound, "failed to resolve chassis: %v", err)
	}
	if !chassis.StreamingSupported {
		return status.Errorf(codes.Unimplemented, "streaming bootstrap is not supported for this device")
	}
	session.chassis = chassis
	log.Infof("Resolved device %s to hostname %s", chassis.ActiveSerial, chassis.Hostname)

	switch idType := lookup.Identity.GetType().(type) {
	case *bpb.Identity_IdevidCert:
		log.Infof("Starting sendIdevidChallenge for TPM 2.0 with IDevID flow for device %s", chassis.ActiveSerial)
		if err := s.sendIdevidChallenge(session, idType.IdevidCert); err != nil {
			return err
		}
		return nil
	case *bpb.Identity_EkPpkPub:
		log.Infof("Starting sendHMACChallenge for TPM 2.0 without IDevID flow for device%s", chassis.ActiveSerial)
		if err := s.sendHMACChallenge(session); err != nil {
			return err
		}
		return nil
	default:
		return status.Errorf(codes.InvalidArgument, "unsupported identity type for re-authentication: %T", idType)
	}
}

func (s *Service) updateStatusAndSendAcknowledgement(session *streamSession) error {
	if err := s.em.SetStatus(session.stream.Context(), session.status); err != nil {
		log.Errorf("Failed to set status for device %s: %v", session.chassis.ActiveSerial, err)
		return status.Errorf(codes.Internal, "failed to set status: %v", err)
	}
	log.Infof("Successfully set status for device %s", session.chassis.ActiveSerial)

	resp := &bpb.BootstrapStreamResponse{
		Type: &bpb.BootstrapStreamResponse_ReportStatusResponse{
			ReportStatusResponse: &bpb.EmptyResponse{},
		},
	}
	if err := session.stream.Send(resp); err != nil {
		return err
	}
	log.Infof("Acknowledged status report from device %s", session.chassis.ActiveSerial)

	return nil
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

// buildEntityLookup constructs an EntityLookup object from a bootstrap request.
func buildEntityLookup(ctx context.Context, req *bpb.BootstrapStreamRequest) (*types.EntityLookup, error) {
	peerAddr, err := peerAddressFromContext(ctx)
	if err != nil {
		return nil, err
	}

	// When the request is a ReportStatusRequest, only serial number and identity are available.
	var cc *bpb.ControlCardState
	var id *bpb.Identity
	var serials []string
	switch reqType := req.GetType().(type) {
	case *bpb.BootstrapStreamRequest_BootstrapRequest:
		cc = reqType.BootstrapRequest.GetControlCardState()
		id = reqType.BootstrapRequest.GetIdentity()
		if cards := reqType.BootstrapRequest.GetChassisDescriptor().GetControlCards(); len(cards) > 0 { // Modular chassis
			for _, v := range cards {
				serials = append(serials, v.GetSerialNumber())
			}
		} else { // Fixed form factor chassis
			serials = append(serials, reqType.BootstrapRequest.GetChassisDescriptor().GetSerialNumber())
		}
	case *bpb.BootstrapStreamRequest_ReportStatusRequest:
		if ccs := reqType.ReportStatusRequest.GetStates(); len(ccs) > 0 {
			cc = ccs[0] // Assume the first control card is the active one.
			for _, v := range ccs {
				serials = append(serials, v.GetSerialNumber())
			}
		}
		id = reqType.ReportStatusRequest.GetIdentity()
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unexpected request type: %T", reqType)
	}
	activeSerial := cc.GetSerialNumber()
	if activeSerial == "" {
		return nil, status.Errorf(codes.InvalidArgument, "no active control card serial number provided in the request")
	}
	if id == nil {
		return nil, status.Errorf(codes.InvalidArgument, "no identity provided in the request")
	}

	log.Infof("Detected identity %+v of device %s from IP %v", id, activeSerial, peerAddr)
	return &types.EntityLookup{
		Serials:      serials,
		ActiveSerial: activeSerial,
		IPAddress:    peerAddr,
		Identity:     id,
	}, nil
}

// New creates a new service.
func New(em EntityManager, tpm20 biz.TPM20Utils) *Service {
	return &Service{
		em:    em,
		tpm20: tpm20,
	}
}
