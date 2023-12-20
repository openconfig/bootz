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

// Package entitymanager is an in-memory implementation of an entity manager that models an organization's inventory.
package entitymanager

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	ownercertificate "github.com/openconfig/bootz/common/owner_certificate"
	"github.com/openconfig/bootz/common/signature"
	"github.com/openconfig/bootz/server/service"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"

	log "github.com/golang/glog"

	bpb "github.com/openconfig/bootz/proto/bootz"
	epb "github.com/openconfig/bootz/server/entitymanager/proto/entity"
	apb "github.com/openconfig/gnsi/authz"
)

const defaultRealm = "prod"

// InMemoryEntityManager provides a simple in memory handler
// for Entities.
type InMemoryEntityManager struct {
	mu sync.Mutex
	// inventory represents an organization's inventory of owned chassis.
	chassisInventory []*epb.Chassis
	// represents the current status of known control cards
	controlCardStatuses map[string]bpb.ControlCardState_ControlCardStatus
	// stores the default config such as security artifacts dir.
	defaults *epb.Options
	// security artifacts  (OVs, OC and PDC).
	// TODO: handle mutlti-vendor case
	secArtifacts *service.SecurityArtifacts
}

// ResolveChassis returns an entity based on the provided lookup.
// If a control card serial is provided, it also looks up chassis' by its control cards.
func (m *InMemoryEntityManager) ResolveChassis(ctx context.Context, lookup *service.EntityLookup, ccSerial string) (*service.Chassis, error) {
	chassis, err := m.lookupChassis(lookup, ccSerial)
	if err != nil {
		return nil, err
	}
	cards := make([]*service.ControlCard, len(chassis.GetControllerCards()))
	for i, controlCard := range chassis.GetControllerCards() {
		cards[i] = &service.ControlCard{
			PartNumber:   controlCard.PartNumber,
			Manufacturer: chassis.GetManufacturer(),
			Serial:       controlCard.GetSerialNumber(),
		}
	}
	bootCfg, err := populateBootConfig(chassis.GetConfig().GetBootConfig())
	if err != nil {
		return nil, err
	}
	authzConf, err := m.populateAuthzConfig(chassis)
	if err != nil {
		return nil, err
	}
	return &service.Chassis{
		Hostname:               chassis.GetName(),
		BootMode:               chassis.GetBootMode(),
		SoftwareImage:          chassis.GetSoftwareImage(),
		Realm:                  defaultRealm,
		Manufacturer:           chassis.GetManufacturer(),
		PartNumber:             chassis.GetPartNumber(),
		Serial:                 chassis.GetSerialNumber(),
		ControlCards:           cards,
		BootConfig:             bootCfg,
		Authz:                  authzConf,
		BootloaderPasswordHash: chassis.GetBootloaderPasswordHash(),
	}, nil
}

func (m *InMemoryEntityManager) lookupChassis(lookup *service.EntityLookup, ccSerial string) (*epb.Chassis, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Search for the chassis first.
	for _, chassis := range m.chassisInventory {
		if chassis.GetManufacturer() == lookup.Manufacturer {
			if chassis.GetSerialNumber() == lookup.SerialNumber {
				return chassis, nil
			}
			// While we're here, try looking up by control card.
			if ccSerial != "" {
				for _, c := range chassis.GetControllerCards() {
					if c.GetSerialNumber() == ccSerial {
						return chassis, nil
					}
				}
			}
		}
	}
	return nil, status.Errorf(codes.NotFound, "could not find chassis for lookup %+v and control card %v", lookup, ccSerial)
}

func readOCConfig(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Error opening file %s: %v", path, err)
	}
	var v any
	err = json.Unmarshal(data, &v)
	if err != nil {
		fmt.Printf("unmarshal error %v", err)
	}
	if !json.Valid(data) {
		return nil, status.Errorf(codes.Internal, "File %s config is not a valid json", path)
	}
	return data, nil
}

func (m *InMemoryEntityManager) populateAuthzConfig(ch *epb.Chassis) (*apb.UploadRequest, error) {
	gnsiConf := ch.GetConfig().GetGnsiConfig()
	gnsiAuthzReq := gnsiConf.GetAuthzUpload()
	gnsiAuthzReqFile := gnsiConf.GetAuthzUploadFile()
	if gnsiAuthzReqFile == "" {
		gnsiAuthzReqFile = m.defaults.GnsiGlobalConfig.GetAuthzUploadFile()
	}
	if gnsiAuthzReq.GetPolicy() != "" && gnsiAuthzReq.GetVersion() != "" {
		return gnsiAuthzReq, nil
	}
	if gnsiAuthzReqFile == "" {
		return nil, status.Errorf(codes.NotFound, "Could not populate authz config, please add config in inventory file")
	}
	data, err := os.ReadFile(gnsiAuthzReqFile)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Error opening file %s: %v", gnsiAuthzReqFile, err)
	}
	gnsiAuthzReq = &apb.UploadRequest{}
	if err := prototext.Unmarshal(data, gnsiAuthzReq); err != nil {
		return nil, status.Errorf(codes.Internal, "File %s config is not a valid authz Upload Request: %v", gnsiAuthzReqFile, err)
	}
	var t any
	err = json.Unmarshal([]byte(gnsiAuthzReq.Policy), &t)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Provided authz policy is not a valid json: %v", err)
	}
	return gnsiAuthzReq, nil
}

func populateBootConfig(conf *epb.BootConfig) (*bpb.BootConfig, error) {
	bootConfig := &bpb.BootConfig{}
	if conf.GetOcConfigFile() != "" {
		ocConf, err := readOCConfig(conf.GetOcConfigFile())
		if err != nil {
			return nil, err
		}
		bootConfig.OcConfig = ocConf
	}
	if len(conf.GetVendorConfig()) > 0 {
		bootConfig.VendorConfig = conf.GetVendorConfig()
	} else if conf.GetVendorConfigFile() != "" {
		cliConf, err := os.ReadFile(string(conf.VendorConfigFile))
		if err != nil {
			return nil, status.Errorf(codes.Internal, "Could not populate vendor config %v", err)
		}
		bootConfig.VendorConfig = cliConf
	}
	// TODO: validate OC and CLI may be added. However, this may prevent negative testing
	bootConfig.Metadata = conf.GetMetadata()
	bootConfig.BootloaderConfig = conf.GetBootloaderConfig()
	return bootConfig, nil
}

// GetBootstrapData fetches and returns the bootstrap data response from the server.
func (m *InMemoryEntityManager) GetBootstrapData(ctx context.Context, chassis *service.Chassis, serial string) (*bpb.BootstrapDataResponse, error) {
	// TODO: Populate gnsi config
	return &bpb.BootstrapDataResponse{
		SerialNum:        serial,
		IntendedImage:    chassis.SoftwareImage,
		BootPasswordHash: chassis.BootloaderPasswordHash,
		ServerTrustCert:  base64.StdEncoding.EncodeToString(m.secArtifacts.TrustAnchor.Raw),
		BootConfig:       chassis.BootConfig,
		Credentials:      &bpb.Credentials{},
		// TODO: Populate pathz, authz and certificates.
		Authz: chassis.Authz,
	}, nil
}

// SetStatus updates the status for each control card on the chassis.
func (m *InMemoryEntityManager) SetStatus(ctx context.Context, req *bpb.ReportStatusRequest) error {
	if len(req.GetStates()) == 0 {
		return status.Errorf(codes.InvalidArgument, "no control card or fixed chassis states provided")
	}
	log.Infof("Bootstrap Status: %v: Status message: %v", req.GetStatus(), req.GetStatusMessage())

	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range req.GetStates() {
		previousStatus, ok := m.controlCardStatuses[c.GetSerialNumber()]
		if !ok {
			previousStatus = bpb.ControlCardState_CONTROL_CARD_STATUS_UNSPECIFIED
			m.controlCardStatuses[c.GetSerialNumber()] = previousStatus
		}
		log.Infof("control card %v changed status from %v to %v", c.GetSerialNumber(), previousStatus, c.GetStatus())
		m.controlCardStatuses[c.GetSerialNumber()] = c.GetStatus()
	}
	return nil
}

// Sign unmarshals the SignedResponse bytes then generates a signature from its Ownership Certificate private key.
func (m *InMemoryEntityManager) Sign(ctx context.Context, resp *bpb.GetBootstrapDataResponse, chassis *service.EntityLookup, controllerCard string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Check if security artifacts are provided for signing.
	if m.secArtifacts == nil {
		return status.Errorf(codes.Internal, "security artifact is missing")
	}
	if len(resp.GetSerializedBootstrapData()) == 0 {
		return status.Errorf(codes.InvalidArgument, "empty serialized bootstrap data")
	}

	sig, err := signature.Sign(m.secArtifacts.OwnerCertPrivateKey, resp.GetSerializedBootstrapData())
	if err != nil {
		return err
	}
	resp.ResponseSignature = sig

	// Populate the OV
	ov, err := m.fetchOwnershipVoucher(controllerCard)
	if err != nil {
		return err
	}
	resp.OwnershipVoucher = ov
	log.Infof("OV populated")

	// Populate the OC
	ocCMS, err := ownercertificate.GenerateCMS(m.secArtifacts.OwnerCert, m.secArtifacts.OwnerCertPrivateKey)
	if err != nil {
		return err
	}
	resp.OwnershipCertificate = ocCMS
	log.Infof("OC populated")
	return nil
}

// fetchOwnershipVoucher retrieves the ownership voucher for a control card
func (m *InMemoryEntityManager) fetchOwnershipVoucher(ccSerial string) ([]byte, error) {
	ov, ok := m.secArtifacts.OV[ccSerial]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "OV not found for serial %v", ccSerial)
	}
	return ov, nil
}

// AddControlCard adds a new control card to the entity manager.
func (m *InMemoryEntityManager) AddControlCard(serial string) *InMemoryEntityManager {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.controlCardStatuses[serial] = bpb.ControlCardState_CONTROL_CARD_STATUS_UNSPECIFIED
	log.Infof("Added control card %v to server entity manager", serial)
	return m
}

// AddChassis adds a new chassis to the entity manager.
func (m *InMemoryEntityManager) AddChassis(bootMode bpb.BootMode, manufacturer string, serial string) *InMemoryEntityManager {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.chassisInventory = append(m.chassisInventory, &epb.Chassis{
		Manufacturer: manufacturer,
		SerialNumber: serial,
		BootMode:     bootMode,
	})
	log.Infof("Added %v chassis %v to server entity manager", manufacturer, serial)
	return m
}

// GetChassisInventory returns the chassis inventory
func (m *InMemoryEntityManager) GetChassisInventory() []*epb.Chassis {
	return m.chassisInventory
}

// New returns a new in-memory entity manager.
func New(chassisConfigFile string, artifacts *service.SecurityArtifacts) (*InMemoryEntityManager, error) {
	newManager := &InMemoryEntityManager{
		controlCardStatuses: map[string]bpb.ControlCardState_ControlCardStatus{},
		defaults:            &epb.Options{GnsiGlobalConfig: &epb.GNSIConfig{}},
		secArtifacts:        artifacts,
	}
	if chassisConfigFile == "" {
		return newManager, nil
	}
	protoTextFile, err := os.ReadFile(chassisConfigFile)
	if err != nil {
		log.Errorf("Error in opening file %s : #%v ", chassisConfigFile, err)
		return nil, err
	}
	entities := epb.Entities{}
	err = prototext.Unmarshal(protoTextFile, &entities)
	if err != nil {
		log.Errorf("Error in un-marshalling %s: %v", protoTextFile, err)
		return nil, err
	}
	log.Infof("New entity manager is initialized successfully from chassis config file %s", chassisConfigFile)
	newManager.chassisInventory = entities.Chassis
	newManager.defaults = entities.GetOptions()
	return newManager, nil
}

// ReplaceDevice replaces an existing chassis with a new chassis object.
// If the chassis is not found, it is added to the inventory.
func (m *InMemoryEntityManager) ReplaceDevice(old *service.EntityLookup, new *epb.Chassis) error {
	// Chassis: old device lookup, newChassis: new device

	// todo: Validate before replace
	// todo: Forward error from validateConfig

	if old == nil || old.SerialNumber == "" {
		return status.Error(codes.InvalidArgument, "chassis serial must be set")
	}

	if new == nil || new.SerialNumber == "" {
		return status.Error(codes.InvalidArgument, "chassis config or serial can not be nil")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	for i, ch := range m.chassisInventory {
		if ch.GetManufacturer() == old.Manufacturer && ch.GetSerialNumber() == old.SerialNumber {
			m.chassisInventory[i] = new
			return nil
		}
	}

	m.chassisInventory = append(m.chassisInventory, new)
	return nil
}

// DeleteDevice removes the chassis at the provided lookup from the entitymanager.
func (m *InMemoryEntityManager) DeleteDevice(chassis *service.EntityLookup) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, ch := range m.chassisInventory {
		if ch.GetManufacturer() == chassis.Manufacturer && ch.GetSerialNumber() == chassis.SerialNumber {
			m.chassisInventory = append(m.chassisInventory[:i], m.chassisInventory[i+1:]...)
		}
	}
}

// GetDevice returns a copy of the chassis at the provided lookup.
func (m *InMemoryEntityManager) GetDevice(chassis *service.EntityLookup) (*epb.Chassis, error) {
	ch, err := m.lookupChassis(chassis, "")
	if err != nil {
		return nil, err
	}
	return proto.Clone(ch).(*epb.Chassis), nil
}

// GetAll returns a copy of the chassisInventory field.
func (m *InMemoryEntityManager) GetAll() []*epb.Chassis {
	m.mu.Lock()
	defer m.mu.Unlock()

	chassisClone := make([]*epb.Chassis, len(m.chassisInventory))

	for i, chassis := range m.chassisInventory {
		chassisClone[i] = proto.Clone(chassis).(*epb.Chassis)
	}

	return chassisClone
}
