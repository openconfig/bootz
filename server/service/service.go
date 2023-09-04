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

// Service that receives bootstrap requests and responds with the relevant data.
package service

import (
	"context"
	"crypto/tls"

	"github.com/openconfig/bootz/proto/bootz"
	"github.com/openconfig/gnmi/errlist"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// OVList is a mapping of control card serial number to ownership voucher.
type OVList map[string]string

// KeyPair is a struct containing PEM-encoded certificates and private keys.
type KeyPair struct {
	Cert string
	Key  string
}

// SecurityArtifacts contains all KeyPairs and OVs needed for the Bootz Server.
// Currently, RSA is the only encryption standard supported by these artifacts.
type SecurityArtifacts struct {
	// The Ownership Certificate is an x509 certificate/private key pair signed by the PDC.
	// The certificate is presented to the device during bootstrapping and is used to validate the Ownership Voucher.
	OC *KeyPair
	// The Pinned Domain Certificate is an x509 certificate/private key pair which acts as a certificate authority on the owner's side.
	// This certificate is included in OVs and is also used to generate a server TLS Cert in this implementation.
	PDC *KeyPair
	// The Vendor CA represents a certificate authority on the vendor side. This CA signs Ownership Vouchers which are verified by the device.
	VendorCA *KeyPair
	// Ownership Vouchers are a list of PKCS7 messages signed by the Vendor CA. There is one per control card.
	OV OVList
	// The TLSKeypair is a TLS certificate used to secure connections between device and server. It is derived from the Pinned Domain Cert.
	TLSKeypair *tls.Certificate
}

// EntityLookup provides a way to resolve chassis and control cards
// in the EntityManager.
type EntityLookup struct {
	Manufacturer string
	SerialNumber string
}

// ChassisEntity provides the mode that the system is currently
// configured.
type ChassisEntity struct {
	BootMode bootz.BootMode
}

// EntityManager maintains the entities and their states.
type EntityManager interface {
	ResolveChassis(*EntityLookup) (*ChassisEntity, error)
	GetBootstrapData(*bootz.ControlCard) (*bootz.BootstrapDataResponse, error)
	SetStatus(*bootz.ReportStatusRequest) error
	Sign(*bootz.GetBootstrapDataResponse, string) error
	FetchOwnershipVoucher(string) (string, error)
}

// Service represents the server and entity manager.
type Service struct {
	bootz.UnimplementedBootstrapServer
	em EntityManager
}

func (s *Service) GetBootstrapData(ctx context.Context, req *bootz.GetBootstrapDataRequest) (*bootz.GetBootstrapDataResponse, error) {
	if len(req.ChassisDescriptor.ControlCards) == 0 {
		return nil, status.Errorf(codes.InvalidArgument, "request must include at least one control card")
	}
	lookup := &EntityLookup{
		Manufacturer: req.ChassisDescriptor.Manufacturer,
		SerialNumber: req.ChassisDescriptor.SerialNumber,
	}
	// Validate the chassis can be serviced
	chassis, err := s.em.ResolveChassis(lookup)

	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to resolve chassis to inventory %+v", req.ChassisDescriptor)
	}

	// If chassis can only be booted into secure mode then return error
	if chassis.BootMode == bootz.BootMode_BOOT_MODE_SECURE && req.Nonce == "" {
		return nil, status.Errorf(codes.InvalidArgument, "chassis requires secure boot only")
	}

	// Iterate over the control cards and fetch data for each card.
	var errs errlist.List

	var responses []*bootz.BootstrapDataResponse
	for _, v := range req.ChassisDescriptor.ControlCards {
		bootdata, err := s.em.GetBootstrapData(v)
		if err != nil {
			errs.Add(err)
		}
		responses = append(responses, bootdata)
	}
	if errs.Err() != nil {
		return nil, errs.Err()
	}

	resp := &bootz.GetBootstrapDataResponse{
		SignedResponse: &bootz.BootstrapDataSigned{
			Responses: responses,
		},
	}
	// Sign the response if Nonce is provided.
	if req.Nonce != "" {
		resp.SignedResponse.Nonce = req.Nonce
		if err := s.em.Sign(resp, req.GetControlCardState().GetSerialNumber()); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to sign bootz response")
		}
	}
	return resp, nil
}

func (s *Service) ReportStatus(ctx context.Context, req *bootz.ReportStatusRequest) (*bootz.EmptyResponse, error) {
	return &bootz.EmptyResponse{}, s.em.SetStatus(req)
}

// SetDeviceConfiguration is a public API for allowing the device configuration to be set for each device the
// will be responsible for configuring.  This will be only availble for testing.
func (s *Service) SetDeviceConfiguration(ctx context.Context) error {
	return status.Errorf(codes.Unimplemented, "Unimplemented")
}

// New creates a new service.
func New(em EntityManager) *Service {
	return &Service{
		em: em,
	}
}
