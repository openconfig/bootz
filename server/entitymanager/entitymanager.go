// Package entitymanager is an in-memory implementation of an entity manager that models an organization's inventory.
package entitymanager

import (
	"github.com/openconfig/bootz/proto/bootz"
	"github.com/openconfig/bootz/server/service"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type InMemoryEntityManager struct{}

func (m *InMemoryEntityManager) ResolveChassis(lookup *service.EntityLookup) (*service.ChassisEntity, error) {
	return nil, status.Errorf(codes.Unimplemented, "Unimplemented")
}

func (m *InMemoryEntityManager) GetBootstrapData(*bootz.ControlCard) (*bootz.BootstrapDataResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "Unimplemented")
}

func (m *InMemoryEntityManager) SetStatus(*bootz.ReportStatusRequest) error {
	return status.Errorf(codes.Unimplemented, "Unimplemented")
}

func (m *InMemoryEntityManager) Sign(*bootz.GetBootstrapDataResponse) error {
	return status.Errorf(codes.Unimplemented, "Unimplemented")
}

func New() *InMemoryEntityManager {
	return &InMemoryEntityManager{}
}
