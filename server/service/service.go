package service

import (
	"context"

	"github.com/openconfig/bootz/proto/bootz"
	//"github.com/openconfig/gnmi/errlist"
	//"google.golang.org/grpc/codes"
	//"google.golang.org/grpc/status"
)

type EntityLookup struct {
	Manufacturer string
	SerialNumber string
	DeviceName string
}

type ChassisEntity struct {}

type EntityManager interface {
	ResolveChassis(EntityLookup) (ChassisEntity, error)
	GetBootstrapData(bootz.ControlCard) (bootz.BootstrapDataResponse, error)
	SetStatus(EntityLookup, bootz.ReportStatusRequest) error
	Sign(resp *bootz.BootstrapDataResponse) error
}

type Service struct {
	bootz.UnimplementedBootstrapServer
	em EntityManager
}

/*func New() (*Service, error){
	return nil,nil
}*/

func (s *Service) GetBootstrapRequest(ctx context.Context, req *bootz.GetBootstrapDataRequest) (*bootz.GetBootstrapDataResponse, error) {
	return nil,nil
	/*if len(req.ChassisDescriptor.ControlCards) == 0 {
		return nil, status.Errorf(codes.InvalidArgument, "request must include at least one control card")
	}
	// Validate the chassis can be serviced
    chassis, err := s.em.ResolveChassis(EntityLookup{
		Manufacturer: req.ChassisDescriptor.Manufacturer,
	    SerialNumber: req.ChassisDescriptor.SerialNumber})
	
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to resolve chassis to inventory %+v", req.ChassisDescriptor)
	}*/

	// If chassis can only be booted into secure mode then return error
	/*if chassis.BootMode == "SecureOnly" && req.Nonce == "" {
	  return nil, status.Errorf(codes.InvalidArgument, "chassis requires secure boot only")
	}*/

	// Iterate over the control cards and fetch data for each card.
	/*var errList errlist.List

	var responses *bootz.BootstrapDataResponse
	for _, v := range req.ChassisDescriptor.ControlCards {
		bootdata, err := errList.Add(s.em.GetBootstrapData(v))
		if err != nil {
			errList.Add(err)
		}
		responses = append(responses, bootdata)
	}
	if len(errList) != 0 {
		return nil, errList.Err()
	}
	resp := &bootz.GetBootstrapDataResponse{
		SignedResponse: &bootz.BootstrapDataSigned{
			Responses: responses,
		},
	}
	// Sign the response if Nonce is provided.
	if req.Nonce != "" {
		if err := s.em.Sign(resp); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to sign bootz response")
		}
	}*/
	return nil, nil
}

func (s *Service) ReportStatus(ctx context.Context, req *bootz.ReportStatusRequest) (*bootz.EmptyResponse, error) {
    // Get device information from metadata
	// Iterate over control cards and set the bootstrap status for element
    /*var errList errlist.List
	for _, v := range req.States {
		if err := s.em.SetStatus(); err != nil {
			errList.Append(err)
		}
	}
    return errlist.Error()*/
	return nil,nil

}

// Public API for allowing the device configuration to be set for each device the 
// will be responsible for configuring.  This will be only availble for testing.
//func (s *Service) SetDeviceConfiguration(ctx context.Context, req entity.ConfigurationRequest) {entity.ConfigurationResonse, error} {
//	return nil, status.Errorf(codes.Unimplemented, "Unimplemented")
//}

func (s *Service) Start() error {
	return nil
}

func New(em EntityManager) *Service {
	return &Service{
		em: em,
	}
}