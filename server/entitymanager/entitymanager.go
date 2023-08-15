// Package entitymanager is an in-memory implementation of an entity manager that models an organization's inventory.
package entitymanager

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"

	"github.com/openconfig/bootz/proto/bootz"
	"github.com/openconfig/bootz/server/service"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	log "github.com/golang/glog"
)

// InMemoryEntityManager provides a simple in memory handler
// for Entities.
type InMemoryEntityManager struct {
	// inventory represents an organization's inventory of owned chassis.
	chassisInventory map[service.EntityLookup]*service.ChassisEntity
	// represents the current status of known control cards
	controlCardStatuses map[string]bootz.ControlCardState_ControlCardStatus
	artifacts           *service.SecurityArtifacts
}

// ResolveChassis returns an entity based on the provided lookup.
func (m *InMemoryEntityManager) ResolveChassis(lookup *service.EntityLookup) (*service.ChassisEntity, error) {
	if e, ok := m.chassisInventory[*lookup]; ok {
		return e, nil
	}

	return nil, status.Errorf(codes.NotFound, "chassis %+v not found in inventory", *lookup)
}

func (m *InMemoryEntityManager) GetBootstrapData(c *bootz.ControlCard) (*bootz.BootstrapDataResponse, error) {
	// First check if we are expecting this control card.
	if c.SerialNumber == "" {
		return nil, status.Errorf(codes.InvalidArgument, "no serial number provided")
	}
	if _, ok := m.controlCardStatuses[c.GetSerialNumber()]; !ok {
		return nil, status.Errorf(codes.NotFound, "control card %v not found in inventory", c.GetSerialNumber())
	}
	// Construct the response. This emulator hardcodes these values but a real Bootz server would not.
	// TODO: Populate these placeholders with realistic ones.
	return &bootz.BootstrapDataResponse{
		SerialNum: c.SerialNumber,
		IntendedImage: &bootz.SoftwareImage{
			Name:          "Default Image",
			Version:       "1.0",
			Url:           "https://path/to/image",
			OsImageHash:   "ABCDEF",
			HashAlgorithm: "SHA256",
		},
		BootPasswordHash: "ABCD123",
		ServerTrustCert:  "FakeTLSCert",
		BootConfig: &bootz.BootConfig{
			VendorConfig: []byte("Vendor Config"),
			OcConfig:     []byte("OC Config"),
		},
		Credentials: &bootz.Credentials{},
		// TODO: Populate pathz, authz and certificates.
	}, nil
}

func (m *InMemoryEntityManager) SetStatus(req *bootz.ReportStatusRequest) error {
	if len(req.GetStates()) == 0 {
		return status.Errorf(codes.InvalidArgument, "no control card states provided")
	}
	log.Infof("Bootstrap Status: %v: Status message: %v", req.GetStatus(), req.GetStatusMessage())

	for _, c := range req.GetStates() {
		previousStatus, ok := m.controlCardStatuses[c.GetSerialNumber()]
		if !ok {
			return status.Errorf(codes.NotFound, "control card %v not found in inventory", c.GetSerialNumber())
		}
		log.Infof("control card %v changed status from %v to %v", c.GetSerialNumber(), previousStatus, c.GetStatus())
		m.controlCardStatuses[c.GetSerialNumber()] = c.GetStatus()
	}
	return nil
}

// Sign unmarshals the SignedResponse bytes then generates a signature from its Ownership Certificate private key.
func (m *InMemoryEntityManager) Sign(resp *bootz.GetBootstrapDataResponse, priv *rsa.PrivateKey) error {
	if resp.GetSignedResponse() == nil {
		return status.Errorf(codes.InvalidArgument, "empty signed response")
	}
	signedResponseBytes, err := proto.Marshal(resp.GetSignedResponse())
	if err != nil {
		return err
	}
	hashed := sha256.Sum256(signedResponseBytes)
	sig, err := rsa.SignPKCS1v15(nil, priv, crypto.SHA256, hashed[:])
	if err != nil {
		return err
	}
	resp.ResponseSignature = string(sig)
	return nil
}

// FetchOwnershipVoucher retrieves the ownership voucher for a control card
func (m *InMemoryEntityManager) FetchOwnershipVoucher(serial string) (string, error) {
	if ov, ok := m.artifacts.OV[serial]; ok {
		return ov, nil
	}
	return "", status.Errorf(codes.NotFound, "OV for serial %v not found", serial)
}

// AddControlCard adds a new control card to the entity manager.
func (m *InMemoryEntityManager) AddControlCard(serial string) *InMemoryEntityManager {
	m.controlCardStatuses[serial] = bootz.ControlCardState_CONTROL_CARD_STATUS_UNSPECIFIED
	return m
}

// AddChassis adds a new chassis to the entity manager.
func (m *InMemoryEntityManager) AddChassis(bootMode bootz.BootMode, manufacturer string, serial string) *InMemoryEntityManager {
	l := service.EntityLookup{
		Manufacturer: manufacturer,
		SerialNumber: serial,
	}
	e := service.ChassisEntity{
		BootMode: bootMode,
	}
	m.chassisInventory[l] = &e
	return m
}

// New returns a new in-memory entity manager.
func New(artifacts *service.SecurityArtifacts) *InMemoryEntityManager {
	return &InMemoryEntityManager{
		artifacts:           artifacts,
		chassisInventory:    make(map[service.EntityLookup]*service.ChassisEntity),
		controlCardStatuses: make(map[string]bootz.ControlCardState_ControlCardStatus),
	}
}
