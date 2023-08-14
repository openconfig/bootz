// Package entitymanager is an in-memory implementation of an entity manager that models an organization's inventory.
package entitymanager

import (
	"github.com/openconfig/bootz/proto/bootz"
	"github.com/openconfig/bootz/server/service"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// InMemoryEntityManager provides a simple in memory handler
// for Entities.
type InMemoryEntityManager struct{}

// ResolveChassis returns an entity based on the provided lookup.
func (m *InMemoryEntityManager) ResolveChassis(lookup *service.EntityLookup) (*service.ChassisEntity, error) {
	return nil, status.Errorf(codes.Unimplemented, "Unimplemented")
}

// GetBootstrapData returns the Bootstrap data for the provided control card.
func (m *InMemoryEntityManager) GetBootstrapData(*bootz.ControlCard) (*bootz.BootstrapDataResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "Unimplemented")
}

// SetStatus returns the current status based on the status request.
func (m *InMemoryEntityManager) SetStatus(*bootz.ReportStatusRequest) error {
	return status.Errorf(codes.Unimplemented, "Unimplemented")
}

// Sign populates the signing fields of the provided Bootstrap data response.
// If fields are set they will be overwritten.
func (m *InMemoryEntityManager) Sign(*bootz.GetBootstrapDataResponse) error {
	return status.Errorf(codes.Unimplemented, "Unimplemented")
}

// New returns a new in-memory entity manager.
func New() *InMemoryEntityManager {
	return &InMemoryEntityManager{}
}
