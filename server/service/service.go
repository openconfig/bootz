package service

import (
	"context"
	"crypto/rsa"

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
type SecurityArtifacts struct {
	OC       *KeyPair
	PDC      *KeyPair
	VendorCA *KeyPair
	OV       OVList
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

type EntityManager interface {
	ResolveChassis(*EntityLookup) (*ChassisEntity, error)
	GetBootstrapData(*bootz.ControlCard) (*bootz.BootstrapDataResponse, error)
	SetStatus(*bootz.ReportStatusRequest) error
	Sign(*bootz.GetBootstrapDataResponse, string, *rsa.PrivateKey) error
	FetchOwnershipVoucher(string) (string, error)
}

type Service struct {
	bootz.UnimplementedBootstrapServer
	em EntityManager
}

func (s *Service) GetBootstrapRequest(ctx context.Context, req *bootz.GetBootstrapDataRequest) (*bootz.GetBootstrapDataResponse, error) {
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
	// TODO: Populate Sign() with an RSA key.
	if req.Nonce != "" {
		if err := s.em.Sign(resp, req.GetControlCardState().GetSerialNumber(), nil); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to sign bootz response")
		}
	}
	return resp, nil
}

func (s *Service) ReportStatus(ctx context.Context, req *bootz.ReportStatusRequest) (*bootz.EmptyResponse, error) {
	return nil, s.em.SetStatus(req)
}

// Public API for allowing the device configuration to be set for each device the
// will be responsible for configuring.  This will be only availble for testing.
func (s *Service) SetDeviceConfiguration(ctx context.Context) error {
	return status.Errorf(codes.Unimplemented, "Unimplemented")
}

func New(em EntityManager) *Service {
	return &Service{
		em: em,
	}
}
