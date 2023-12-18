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
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"net"

	"github.com/openconfig/gnmi/errlist"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	log "github.com/golang/glog"
	bpb "github.com/openconfig/bootz/proto/bootz"
	apb "github.com/openconfig/gnsi/authz"
)

// OVList is a mapping of control card serial number to ownership voucher.
type OVList map[string][]byte

// SecurityArtifacts contains all KeyPairs and OVs needed for the Bootz Server.
// Currently, RSA is the only encryption standard supported by these artifacts.
type SecurityArtifacts struct {
	// The Ownership Certificate is an x509 certificate/private key pair signed by the PDC.
	// The certificate is presented to the device during bootstrapping and is used to validate the Ownership Voucher.
	OwnerCert           *x509.Certificate
	OwnerCertPrivateKey crypto.PrivateKey
	// The Pinned Domain Certificate is an x509 certificate/private key pair which acts as a certificate authority on the owner's side.
	// This certificate is included in OVs.
	PDC           *x509.Certificate
	PDCPrivateKey crypto.PrivateKey
	// The Vendor CA represents a certificate authority on the vendor side. This CA signs Ownership Vouchers which are verified by the device.
	VendorCA           *x509.Certificate
	VendorCAPrivateKey crypto.PrivateKey
	// The Trust Anchor is a self signed CA used to generate the TLS certificate.
	TrustAnchor           *x509.Certificate
	TrustAnchorPrivateKey crypto.PrivateKey
	// Ownership Vouchers are a list of PKCS7 messages signed by the Vendor CA. There is one per control card.
	OV OVList
	// The TLSKeypair is a TLS certificate used to secure connections between device and server. It is derived from the Trust Anchor.
	TLSKeypair *tls.Certificate
}

// EntityLookup is used to resolve the fields of an active control card to a chassis.
// For fixed form factor devices, the active control card is the chassis itself.
type EntityLookup struct {
	// The manufacturer of this control card or chassis.
	Manufacturer string
	// The serial number of this control card or chassis.
	SerialNumber string
	// The hardware model/part number of this control card or chassis.
	PartNumber string
	// The reported IP address of the management interface for this control
	// card or chassis.
	IPAddress string
	// Whether this chassis appears to be a modular device.
	Modular bool
}

// Describes a Chassis that has been resolved from an organization's inventory.
type Chassis struct {
	// The intended hostname of the chassis.
	Hostname string
	// The mode this chassis should boot into.
	BootMode bpb.BootMode
	// The intended software image to install on the device.
	SoftwareImage *bpb.SoftwareImage
	// The realm this chassis exists in, typically lab or prod.
	Realm string
	// The manufacturer of this chassis.
	Manufacturer string
	// The part number of this chassis.
	PartNumber string
	// The serial number of this chassis.
	Serial string
	// Describes the control cards that exist in this chassis.
	ControlCards []*ControlCard
	// The below fields are normally unset and are primarily used for
	// cases where this data should be hardcoded e.g. for testing.
	BootConfig             *bpb.BootConfig
	Authz                  *apb.UploadRequest
	BootloaderPasswordHash string
}

// Describes a control card that exists in a resolved Chassis.
type ControlCard struct {
	Manufacturer string
	PartNumber   string
	Serial       string
}

// buildEntityLookup constructs an EntityLookup object from a bootstrap request.
func buildEntityLookup(ctx context.Context, req *bpb.GetBootstrapDataRequest) (*EntityLookup, error) {
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
	lookup := &EntityLookup{
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
	ResolveChassis(context.Context, *EntityLookup, string) (*Chassis, error)
	GetBootstrapData(context.Context, *Chassis, string) (*bpb.BootstrapDataResponse, error)
	SetStatus(context.Context, *bpb.ReportStatusRequest) error
	Sign(context.Context, *bpb.GetBootstrapDataResponse, *EntityLookup, string) error
}

// Service represents the server and entity manager.
type Service struct {
	bpb.UnimplementedBootstrapServer
	em EntityManager
}

func (s *Service) GetBootstrapData(ctx context.Context, req *bpb.GetBootstrapDataRequest) (*bpb.GetBootstrapDataResponse, error) {
	log.Infof("=============================================================================")
	log.Infof("==================== Received request for bootstrap data ====================")
	log.Infof("=============================================================================")
	peerAddr, err := peerAddressFromContext(ctx)
	if err != nil {
		return nil, err
	}
	log.Infof("Received GetBootstrapData request from %v", peerAddr)
	fixedChasis := true
	ccSerial := ""
	chassisDesc := req.GetChassisDescriptor()
	if len(chassisDesc.GetControlCards()) >= 1 {
		fixedChasis = false
		ccSerial = chassisDesc.GetControlCards()[0].GetSerialNumber()
	}
	log.Infof("Requesting for %v chassis %v", chassisDesc.GetManufacturer(), chassisDesc.GetSerialNumber())
	lookup := &EntityLookup{
		Manufacturer: chassisDesc.GetManufacturer(),
		SerialNumber: chassisDesc.GetSerialNumber(),
		PartNumber:   chassisDesc.GetPartNumber(),
		IPAddress:    peerAddr,
	}
	// Validate the chassis can be serviced
	chassis, err := s.em.ResolveChassis(ctx, lookup, ccSerial)
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
	if fixedChasis {
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
		if err := s.em.Sign(ctx, resp, lookup, req.GetControlCardState().GetSerialNumber()); err != nil {
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
	return &bpb.EmptyResponse{}, s.em.SetStatus(ctx, req)
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
