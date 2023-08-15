package service

import (
	"context"
	"time"

	//"time"

	"github.com/openconfig/bootz/proto/bootz"
	//"google.golang.org/grpc"
	"github.com/openconfig/gnmi/errlist"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ChassisEntity provides the mode that the system is currently
// configured.
type ChassisEntity struct {
	Name     string
	BootMode bootz.BootMode
}

type bootLog struct {
	BootMode       bootz.BootMode
	StartTimeStamp uint64
	EndTimeStamp   uint64
	Status         []bootz.ReportStatusRequest_BootstrapStatus
	BootResponse   *bootz.BootstrapDataResponse
	BootRequest    *bootz.GetBootstrapDataRequest
	Err            error
}
type EntityManager interface {
	ResolveChassis(*bootz.ChassisDescriptor) (*ChassisEntity, error)
	GetBootstrapData(*bootz.GetBootstrapDataRequest, *bootz.ControlCard) (*bootz.BootstrapDataResponse, error)
	//SetStatus(EntityLookup, bootz.ReportStatusRequest) error
	Sign(resp *bootz.GetBootstrapDataResponse) error
}

type Service struct {
	bootz.UnimplementedBootstrapServer

	em               EntityManager
	connectedChassis map[string]*bootz.ChassisDescriptor
	activeBoots      map[string]*bootLog
	failedRequest    map[*bootz.GetBootstrapDataRequest]error
}

/*func New() (*Service, error){
	return nil,nil
}*/

func (s *Service) GetBootstrapRequest(ctx context.Context, req *bootz.GetBootstrapDataRequest) (*bootz.GetBootstrapDataResponse, error) {
	if len(req.ChassisDescriptor.ControlCards) == 0 {
		s.failedRequest[req] = status.Errorf(codes.InvalidArgument, "request must include at least one control card")
		return nil, status.Errorf(codes.InvalidArgument, "request must include at least one control card")
	}
	// Validate the chassis can be serviced
	chassis, err := s.em.ResolveChassis(req.ChassisDescriptor)

	if err != nil {
		s.failedRequest[req] = status.Errorf(codes.InvalidArgument, "failed to resolve chassis to inventory, error from IM: %v", err)
		return nil, status.Errorf(codes.InvalidArgument, "failed to resolve chassis to inventory %+v", req.ChassisDescriptor)
	}
	s.connectedChassis[chassis.Name] = req.ChassisDescriptor

	// If chassis can only be booted into secure mode then return error
	if chassis.BootMode == bootz.BootMode_BOOT_MODE_SECURE && req.Nonce == "" {
		return nil, status.Errorf(codes.InvalidArgument, "chassis requires secure boot only")
	}

	// Iterate over the control cards and fetch data for each card.
	var errs errlist.Error

	var responses []*bootz.BootstrapDataResponse
	for _, v := range req.ChassisDescriptor.ControlCards {
		bootdata, err := s.em.GetBootstrapData(req, v)
		s.activeBoots[v.GetSerialNumber()] = &bootLog{
			BootMode:       chassis.BootMode,
			StartTimeStamp: uint64(time.Now().UnixMilli()),
			BootRequest:    req,
			Err:            err,
			BootResponse:   bootdata,
			Status:         []bootz.ReportStatusRequest_BootstrapStatus{bootz.ReportStatusRequest_BootstrapStatus(req.ControlCardState.Status)},
		}
		if err != nil {
			errs.Add(err)
			s.activeBoots[v.GetSerialNumber()].EndTimeStamp = uint64(time.Now().UnixMilli())
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
		if err := s.em.Sign(resp); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to sign bootz response")
		}
	}
	return nil, nil
}

func (s *Service) ReportStatus(ctx context.Context, req *bootz.ReportStatusRequest) (*bootz.EmptyResponse, error) {
	// Get device information from metadata
	// Iterate over control cards and set the bootstrap status for element
	var errList errlist.List
	for _, v := range req.States {
		bootLog, ok := s.activeBoots[v.SerialNumber]
		if !ok {
			// TODO: this will lead to issues if the server restarts with the current code.
			// later we need fix this, either not return the error or add a way to recover active boots logs when server restarts
			errList.Add(status.Errorf(codes.InvalidArgument, "getting status request for controller card %s is not expected, the card never requested boot data", v.SerialNumber))
			continue
		}
		bootLog.Status = append(bootLog.Status, bootz.ReportStatusRequest_BootstrapStatus(v.Status))
		if v.Status == bootz.ControlCardState_CONTROL_CARD_STATUS_INITIALIZED {
			bootLog.EndTimeStamp = uint64(time.Now().UnixMilli())
		}
	}
	if errList.Err() != nil {
		return &bootz.EmptyResponse{}, nil

	}
	return nil, errList.Err()
}

// Public API for allowing the device configuration to be set for each device the
// will be responsible for configuring.  This will be only available for testing.
//func (s *Service) SetDeviceConfiguration(ctx context.Context, req entity.ConfigurationRequest) {entity.ConfigurationResonse, error} {
//	return nil, status.Errorf(codes.Unimplemented, "Unimplemented")
//}

func (s *Service) Start() error {
	return nil
}

func New(em EntityManager) *Service {
	// initialize the maps
	return &Service{
		em:               em,
		connectedChassis: map[string]*bootz.ChassisDescriptor{},
		activeBoots:      map[string]*bootLog{},
		failedRequest:    map[*bootz.GetBootstrapDataRequest]error{},
	}
}
