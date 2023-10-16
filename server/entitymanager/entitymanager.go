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
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"

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

var (
	rxBase64 = regexp.MustCompile(`^(?:[A-Za-z0-9+\\/]{4})*(?:[A-Za-z0-9+\\/]{2}==|[A-Za-z0-9+\\/]{3}=|[A-Za-z0-9+\\/]{4})$`)
)

// InMemoryEntityManager provides a simple in memory handler
// for Entities.
type InMemoryEntityManager struct {
	mu sync.Mutex
	// inventory represents an organization's inventory of owned chassis.
	chassisInventory map[service.EntityLookup]*epb.Chassis
	// represents the current status of known control cards
	controlCardStatuses map[string]bpb.ControlCardState_ControlCardStatus
	// stores the default config such as security artifacts dir.
	defaults *epb.Options
	// security artifacts  (OVs, OC and PDC).
	// TODO: handle mutlti-vendor case
	secArtifacts *service.SecurityArtifacts
}

// ResolveChassis returns an entity based on the provided lookup.
// In cases when the serial for modular chassis is not set, it uses the controller card to find the chassis.
func (m *InMemoryEntityManager) ResolveChassis(lookup *service.EntityLookup, ccSerial string) (*service.ChassisEntity, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	chassis, found := m.chassisInventory[*lookup]
	if !found {
		if lookup.SerialNumber == "" && ccSerial != "" {
			ch, err := m.resolveChassisViaControllerCard(lookup, ccSerial)
			if err != nil {
				return nil, status.Errorf(codes.NotFound, "Could not find chassis with serial#: %s and manufacturer: %s and controller card %s",
					lookup.SerialNumber, lookup.Manufacturer, ccSerial)
			}
			chassis = ch
		} else {
			return nil, status.Errorf(codes.NotFound, "Could not find chassis with serial#: %s and manufacturer: %s and controller card %s",
				lookup.SerialNumber, lookup.Manufacturer, ccSerial)
		}
	}
	return &service.ChassisEntity{BootMode: chassis.GetBootMode()}, nil
}

// resolveChassisViaControllerCard resolves a chassis based on controller card serial.
func (m *InMemoryEntityManager) resolveChassisViaControllerCard(lookup *service.EntityLookup, ccSerial string) (*epb.Chassis, error) {
	for _, ch := range m.chassisInventory {
		for _, c := range ch.GetControllerCards() {
			if c.GetSerialNumber() == ccSerial {
				if ch.Manufacturer != lookup.Manufacturer {
					continue
				}
				return ch, nil
			}
		}
	}
	return nil, status.Errorf(codes.NotFound, "could not find chassis for controller card with serial# %s", ccSerial)
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
	if conf.GetVendorConfigFile() != "" {
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
func (m *InMemoryEntityManager) GetBootstrapData(el *service.EntityLookup, controllerCard *bpb.ControlCard) (*bpb.BootstrapDataResponse, error) {
	// First check if we are expecting this control card.
	serial := ""
	fixedChassis := false
	if controllerCard == nil {
		if el.SerialNumber == "" {
			return nil, status.Errorf(codes.InvalidArgument, "chassis type (fixed/modular) can not be determined, either controller card or chassis serial must be set ")
		}
		fixedChassis = true
		serial = el.SerialNumber
	}
	if !fixedChassis {
		serial = controllerCard.SerialNumber
	}
	// Check if the controller card and related chassis can be solved.
	var chassis *epb.Chassis
	found := false
	m.mu.Lock()
	defer m.mu.Unlock()
	log.Infof("Fetching data for controller card/chassis %v", serial)
	if fixedChassis {
		chassis, found = m.chassisInventory[*el]
		if !found { // fixed chassis must have serial
			return nil, status.Errorf(codes.NotFound, "could not find fixed chassis with serial#: %s and manufacturer: %s", chassis.SerialNumber, chassis.Manufacturer)
		}
	} else {
		found = false
	out:
		for _, ch := range m.chassisInventory {
			for _, c := range ch.GetControllerCards() {
				if c.GetSerialNumber() == controllerCard.GetSerialNumber() && c.GetPartNumber() == controllerCard.PartNumber {
					if ch.Manufacturer != el.Manufacturer {
						continue
					}
					chassis = ch
					found = true
					break out
				}
			}
		}
		if !found {
			return nil, status.Errorf(codes.NotFound, "could not find controller card with serial# %s", serial)
		}
	}
	log.Infof("Control card located in inventory")
	// TODO: for now add status for the controller card. We may need to move all runtime info to bootz service.
	m.controlCardStatuses[serial] = bpb.ControlCardState_CONTROL_CARD_STATUS_UNSPECIFIED
	bootCfg, err := populateBootConfig(chassis.GetConfig().GetBootConfig())
	if err != nil {
		return nil, err
	}
	authzConf, err := m.populateAuthzConfig(chassis)
	if err != nil {
		return nil, err
	}

	// TODO: Populate ServerTrustCert and gnsi config
	return &bpb.BootstrapDataResponse{
		SerialNum:        serial,
		IntendedImage:    chassis.GetSoftwareImage(),
		BootPasswordHash: chassis.BootloaderPasswordHash,
		ServerTrustCert:  "FakeTLSCert",
		BootConfig:       bootCfg,
		Credentials:      &bpb.Credentials{},
		// TODO: Populate pathz, authz and certificates.
		Authz: authzConf,
	}, nil
}

// SetStatus updates the status for each control card on the chassis.
func (m *InMemoryEntityManager) SetStatus(req *bpb.ReportStatusRequest) error {
	if len(req.GetStates()) == 0 {
		return status.Errorf(codes.InvalidArgument, "no control card or fixed chassis states provided")
	}
	log.Infof("Bootstrap Status: %v: Status message: %v", req.GetStatus(), req.GetStatusMessage())

	m.mu.Lock()
	defer m.mu.Unlock()
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

// // readKeyPair reads the cert/key pair from the specified directory.
// Certs must have the format {name}_pub.pem and keys must have the format {name}_priv.pem
func readKeypair(dir, name string) (*service.KeyPair, error) {
	cert, err := os.ReadFile(filepath.Join(dir, fmt.Sprintf("%v_pub.pem", name)))
	if err != nil {
		return nil, fmt.Errorf("unable to read %v cert: %v", name, err)
	}
	privateKey, err := os.ReadFile(filepath.Join(dir, fmt.Sprintf("%v_priv.pem", name)))
	if err != nil {
		return nil, fmt.Errorf("unable to read %v key: %v", name, err)
	}
	return &service.KeyPair{
		Cert:       string(cert),
		PrivateKey: string(privateKey),
	}, nil
}

// loadServerTLSCert uses the PDC key as the server certificate.
func loadServerTLSCert(pdc *service.KeyPair) (*tls.Certificate, error) {
	tlsCert, err := tls.X509KeyPair([]byte(pdc.Cert), []byte(pdc.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("unable to load PDC keys %v", err)
	}
	return &tlsCert, err
}

// parseSecurityArtifacts reads from the specified directory to find the required keypairs and ownership vouchers.
func parseSecurityArtifacts(artifactDir string) (*service.SecurityArtifacts, error) {
	oc, err := readKeypair(artifactDir, "oc")
	if err != nil {
		return nil, err
	}
	pdc, err := readKeypair(artifactDir, "pdc")
	if err != nil {
		return nil, err
	}
	vendorCA, err := readKeypair(artifactDir, "vendorca")
	if err != nil {
		return nil, err
	}
	// use pdc key as server cer
	tlsCert, err := loadServerTLSCert(pdc)
	if err != nil {
		return nil, err
	}
	return &service.SecurityArtifacts{
		OC:         oc,
		PDC:        pdc,
		VendorCA:   vendorCA,
		TLSKeypair: tlsCert,
	}, nil
}

// isBase64 check if a string is base64 encoded.
func isBase64(str string) bool {
	return rxBase64.MatchString(str)
}

// Sign unmarshals the SignedResponse bytes then generates a signature from its Ownership Certificate private key.
func (m *InMemoryEntityManager) Sign(resp *bpb.GetBootstrapDataResponse, chassis *service.EntityLookup, controllerCard string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Check if security artifacts are provided for signing.
	if m.secArtifacts == nil {
		return status.Errorf(codes.Internal, "security artifact is missing")
	}
	if resp.GetSignedResponse() == nil {
		return status.Errorf(codes.InvalidArgument, "empty signed response")
	}

	log.Infof("Marshalling the response...")
	signedResponseBytes, err := proto.Marshal(resp.GetSignedResponse())
	if err != nil {
		return err
	}
	log.Infof("Successfully serialized the response")
	block, _ := pem.Decode([]byte(m.secArtifacts.OC.PrivateKey))
	if block == nil {
		return fmt.Errorf("unable to decode private key")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	sig, err := signature.Create(priv, signedResponseBytes)
	if err != nil {
		return err
	}
	resp.ResponseSignature = sig

	// Populate the OV
	ov, err := m.fetchOwnershipVoucher(chassis, controllerCard)
	if err != nil {
		return err
	}
	ovByte := []byte(ov)
	if isBase64(ov) {
		ovByte, err = base64.StdEncoding.DecodeString(ov)
		if err != nil {
			return status.Errorf(codes.Internal, "unable to decode ov from base64")
		}
	}
	resp.OwnershipVoucher = ovByte
	log.Infof("OV populated")

	// Populate the OC
	resp.OwnershipCertificate = []byte(m.secArtifacts.OC.Cert)
	log.Infof("OC populated")
	return nil
}

// fetchOwnershipVoucher retrieves the ownership voucher for a control card
func (m *InMemoryEntityManager) fetchOwnershipVoucher(lookup *service.EntityLookup, ccSerial string) (string, error) {
	chassis, ok := m.chassisInventory[*lookup]
	if !ok {
		if lookup.SerialNumber == "" {
			chassis, _ = m.resolveChassisViaControllerCard(lookup, ccSerial)
			if chassis == nil {
				return "", status.Errorf(codes.NotFound, "could not find chassis for controller car #: %s", ccSerial)
			}
		}
	}
	for _, c := range chassis.GetControllerCards() {
		if c.GetSerialNumber() == ccSerial {
			return c.GetOwnershipVoucher(), nil
		}
	}
	// Handle fixed chassis.
	if len(chassis.GetControllerCards()) == 0 {
		return chassis.GetOwnershipVoucher(), nil
	}
	return "", status.Errorf(codes.NotFound, "could not find controller card or fixed chassis with serial#: %s", ccSerial)
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
	l := service.EntityLookup{
		Manufacturer: manufacturer,
		SerialNumber: serial,
	}
	m.chassisInventory[l] = &epb.Chassis{
		Manufacturer: manufacturer,
		SerialNumber: serial,
		BootMode:     bootMode,
	}
	log.Infof("Added %v chassis %v to server entity manager", manufacturer, serial)
	return m
}

// GetChassisInventory returns the chassis inventory
func (m *InMemoryEntityManager) GetChassisInventory() map[service.EntityLookup]*epb.Chassis {
	return m.chassisInventory
}

// New returns a new in-memory entity manager.
func New(chassisConfigFile string) (*InMemoryEntityManager, error) {
	newManager := &InMemoryEntityManager{
		chassisInventory:    map[service.EntityLookup]*epb.Chassis{},
		controlCardStatuses: map[string]bpb.ControlCardState_ControlCardStatus{},
		defaults:            &epb.Options{GnsiGlobalConfig: &epb.GNSIConfig{}},
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
	for _, ch := range entities.Chassis {
		lookup := service.EntityLookup{
			Manufacturer: ch.GetManufacturer(),
			SerialNumber: ch.GetSerialNumber(),
		}
		newManager.chassisInventory[lookup] = ch
	}
	newManager.defaults = entities.GetOptions()
	if newManager.defaults.ArtifactDir != "" {
		newManager.secArtifacts, err = parseSecurityArtifacts(entities.Options.ArtifactDir)
		if err != nil {
			log.Errorf("Error in parsing security artifacts : %v", err)
			return nil, fmt.Errorf("error in parsing security artifacts : %v", err)
		}
	}

	return newManager, nil
}

// ReplaceDevice replaces an existing chassis with a new chassis object.
func (m *InMemoryEntityManager) ReplaceDevice(chassis *service.EntityLookup, newChassis *epb.Chassis) error {
	// Chassis: old device lookup, newChassis: new device

	// todo: Validate before replace
	// todo: Forward error from validateConfig

	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.chassisInventory, *chassis)

	lookup := service.EntityLookup{
		Manufacturer: newChassis.GetManufacturer(),
		SerialNumber: newChassis.GetSerialNumber(),
	}

	m.chassisInventory[lookup] = newChassis

	// This method will be able to return an error when validation is added.
	return nil
}

// DeleteDevice removes the chassis at the provided lookup from the entitymanager.
func (m *InMemoryEntityManager) DeleteDevice(chassis *service.EntityLookup) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.chassisInventory, *chassis)
}

// GetDevice returns a copy of the chassis at the provided lookup.
func (m *InMemoryEntityManager) GetDevice(chassis *service.EntityLookup) (*epb.Chassis, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if val, exists := m.chassisInventory[*chassis]; exists {
		return proto.Clone(val).(*epb.Chassis), nil
	}

	return nil, status.Errorf(codes.NotFound, "Could not find chassis with serial#: %s and manufacturer: %s", chassis.SerialNumber, chassis.Manufacturer)
}

// GetAll returns a copy of the chassisInventory field.
func (m *InMemoryEntityManager) GetAll() map[service.EntityLookup]*epb.Chassis {
	m.mu.Lock()
	defer m.mu.Unlock()

	chassisMapClone := make(map[service.EntityLookup]*epb.Chassis)

	for lookup, chassis := range m.chassisInventory {
		chassisMapClone[lookup] = proto.Clone(chassis).(*epb.Chassis)
	}

	return chassisMapClone
}
