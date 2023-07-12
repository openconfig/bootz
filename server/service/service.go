package service

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"github.com/openconfig/bootz/proto/bootz"
)

type EntityLookup struct {
	Manufacturer string
	SerialNumber string
	DeviceName string
}

type ChassisEntity struct {}

type EntityManager interface {
	ResolveChassis(EntityLookup) (ChassisEntity, error)
	GetBootConfig(bootz.ControlCard) (bootz.BootConfig, error)
	SetStatus(EntityLookup, bootz.ReportStatusRequest) error
}

type Service struct {
	bootz.UnimplementedBootstrapServer
	em EntityManager
}

func (s *Service) GetBootstrapRequest(ctx context.Context, req bootz.GetBootstrapDataRequest) (*bootz.GetBootstrapDataResponse, error) {
	if len(req.ChassisDescriptor.ControlCards) == 0 {
		return nil, status.Errorf(codes.InvalidArgument, "request must include at least one control card")
	}
	// Validate the chassis can be serviced
    chassis, err := s.em.ResolveChassis(
		req.ChassisDescriptor.Manufacturer,
	    req.ChassisDescriptor.SerialNumber)
	
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to resolve chassis to inventory %+v", req.ChassisDescriptor)
	}

	// If chassis can only be booted into secure mode then return error
	if chassis.BootMode == "SecureOnly" && req.Nonce == "" {
	  return nil, status.Errorf(codes.InvalidArgument, "chassis requires secure boot only")
	}
	
	// Iterate over the control cards and fetch data for each card.
	for _, v := range req.ChassisDescriptor.ControlCards {
		s.em.GetBootConfig(v)
	}
	return nil, nil
}

func (s *Service) ReportStatus(ctx context.Context, req bootz.ReportStatusRequest) (*bootz.EmptyResponse, error) {
    // Get device information from metadata
	// Iterate over control cards and set the bootstrap status for element
    var errList errlist.List
	for _, v := range req.ControlCards {
		if err := s.em.SetStatus(); err != nil {
			errList.Append(err)
		}
	}
    return errlist.Error()

}

// Public API for allowing the device configuration to be set for each device the 
// will be responsible for configuring.  This will be only availble for testing.
func (s *Service) SetDeviceConfiguration(ctx context.Context, req entity.ConfigurationRequest) {entity.ConfigurationResonse, error} {
	return nil, status.Errorf(codes.Unimplemented, "Unimplemented")
}

func (s *Service) Start() error {
	return nil
}

func New(em EntityManager) *Service {
	return &Service{
		em: em
	}
}