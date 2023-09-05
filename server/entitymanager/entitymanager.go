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
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/openconfig/bootz/proto/bootz"
	"github.com/openconfig/bootz/server/service"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"google.golang.org/protobuf/encoding/prototext"

	log "github.com/golang/glog"
	epb "github.com/openconfig/bootz/server/entitymanager/proto/entity"
	gpb "github.com/openconfig/gnmi/proto/gnmi"
)

// InMemoryEntityManager provides a simple in memory handler
// for Entities.
type InMemoryEntityManager struct {
	mu sync.Mutex
	// inventory represents an organization's inventory of owned chassis.
	chassisInventory map[service.EntityLookup]*epb.Chassis
	// represents the current status of known control cards
	controlCardStatuses map[string]bootz.ControlCardState_ControlCardStatus
	// stores the defaut config such as security artifacts dir.
	defaults *epb.Options
	// security artifacts  (OVs, OC and PDC).
	// TODO: handle mutlti-vendor case
	secArtifacts *service.SecurityArtifacts
}

// ResolveChassis returns an entity based on the provided lookup.
func (m *InMemoryEntityManager) ResolveChassis(chassis *service.EntityLookup) (*service.ChassisEntity, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ch, ok := m.chassisInventory[*chassis]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "Could not find chassis with serial#: %s and manufacturer: %s", chassis.SerialNumber, chassis.Manufacturer)
	}
	return &service.ChassisEntity{BootMode: ch.GetBootMode()}, nil
}

func readOCConfig(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Error opening file %s: %v", path, err)
	}
	req := &gpb.SetRequest{}
	if err := prototext.Unmarshal(data, req); err != nil {
		return nil, status.Errorf(codes.Internal, "File %s config is not a valid gnmi Setrequest: %v", path, err)
	}
	return data, nil
}

func populateBootConfig(conf *epb.BootConfig) (*bootz.BootConfig, error) {
	bootConfig := &bootz.BootConfig{}
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
func (m *InMemoryEntityManager) GetBootstrapData(chassis *service.EntityLookup, controllerCard *bootz.ControlCard) (*bootz.BootstrapDataResponse, error) {
	// First check if we are expecting this control card.
	if controllerCard.SerialNumber == "" {
		return nil, status.Errorf(codes.InvalidArgument, "no serial number provided")
	}
	// Check if the controller card and related chassis can be solved.
	m.mu.Lock()
	defer m.mu.Unlock()
	log.Infof("Fetching data for %v", controllerCard.SerialNumber)
	ch, ok := m.chassisInventory[*chassis]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "could not find chassis with serial#: %s and manufacturer: %s", chassis.SerialNumber, chassis.Manufacturer)
	}
	found := false
	for _, c := range ch.GetControllerCards() {
		if c.GetSerialNumber() == controllerCard.GetSerialNumber() && c.GetPartNumber() == controllerCard.PartNumber {
			found = true
			break
		}
	}
	if !found {
		return nil, status.Errorf(codes.NotFound, "could not find Controller with serial#: %s and partnumber: %s belonging to chassis %s", controllerCard.GetSerialNumber(), controllerCard.GetPartNumber(), chassis.SerialNumber)
	}
	// TODO: for now add status for the controller card. We may need to move all runtime info to bootz service.
	m.controlCardStatuses[controllerCard.GetSerialNumber()] = bootz.ControlCardState_CONTROL_CARD_STATUS_UNSPECIFIED

	bootCfg, err := populateBootConfig(ch.GetConfig().GetBootConfig())
	if err != nil {
		return nil, err
	}
	log.Infof("Control card located in inventory")

	// TODO: Populate ServerTrustCert and gnsi config
	return &bootz.BootstrapDataResponse{
		SerialNum:        controllerCard.SerialNumber,
		IntendedImage:    ch.GetSoftwareImage(),
		BootPasswordHash: ch.BootloaderPasswordHash,
		ServerTrustCert:  "FakeTLSCert",
		BootConfig:       bootCfg,
		Credentials:      &bootz.Credentials{},
		// TODO: Populate pathz, authz and certificates.
	}, nil
}

// SetStatus updates the status for each control card on the chassis.
func (m *InMemoryEntityManager) SetStatus(req *bootz.ReportStatusRequest) error {
	if len(req.GetStates()) == 0 {
		return status.Errorf(codes.InvalidArgument, "no control card states provided")
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
	key, err := os.ReadFile(filepath.Join(dir, fmt.Sprintf("%v_priv.pem", name)))
	if err != nil {
		return nil, fmt.Errorf("unable to read %v key: %v", name, err)
	}
	return &service.KeyPair{
		Cert: string(cert),
		Key:  string(key),
	}, nil
}

// loadServerTLSCert uses the PDC key as the server certificate.
func loadServerTLSCert(pdc *service.KeyPair) (*tls.Certificate, error) {
	tlsCert, err := tls.X509KeyPair([]byte(pdc.Cert), []byte(pdc.Key))
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

// Sign unmarshals the SignedResponse bytes then generates a signature from its Ownership Certificate private key.
func (m *InMemoryEntityManager) Sign(resp *bootz.GetBootstrapDataResponse, chassis *service.EntityLookup, controllerCard string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	// check if sec artifacts areprovided for signing
	if m.secArtifacts == nil {
		return status.Errorf(codes.Internal, "security artifact is missing")
	}
	log.Infof("Decoding the OC private key...")
	block, _ := pem.Decode([]byte(m.secArtifacts.OC.Key))
	if block == nil {
		return status.Errorf(codes.Internal, "unable to decode OC private key")
	}
	log.Infof("Decoded the OC private key")

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	if resp.GetSignedResponse() == nil {
		return status.Errorf(codes.InvalidArgument, "empty signed response")
	}

	log.Infof("Marshalling the response...")
	signedResponseBytes, err := proto.Marshal(resp.GetSignedResponse())
	if err != nil {
		return err
	}
	log.Infof("Sucessfully serialized the response")

	log.Infof("Calculating the sha256 sum to encrypt the response...")
	hashed := sha256.Sum256(signedResponseBytes)
	// TODO: Add support for EC keys too.
	log.Infof("Encrypting the response...")
	sig, err := rsa.SignPKCS1v15(nil, priv, crypto.SHA256, hashed[:])
	if err != nil {
		return err
	}
	resp.ResponseSignature = base64.StdEncoding.EncodeToString(sig)
	log.Infof("Response signature set")

	// Populate the OV
	ov, err := m.fetchOwnershipVoucher(chassis, controllerCard)
	if err != nil {
		return err
	}
	resp.OwnershipVoucher = []byte(ov)
	log.Infof("OV populated")

	// Populate the OC
	resp.OwnershipCertificate = []byte(m.secArtifacts.OC.Cert)
	log.Infof("OC populated")
	return nil
}

// FetchOwnershipVoucher retrieves the ownership voucher for a control card
func (m *InMemoryEntityManager) fetchOwnershipVoucher(chassis *service.EntityLookup, ccSerial string) (string, error) {
	ch, ok := m.chassisInventory[*chassis]
	if !ok {
		return "", status.Errorf(codes.NotFound, "could not find chassis with serial#: %s and manufacturer: %s", chassis.SerialNumber, chassis.Manufacturer)
	}
	//cc:=&bootz.ControlCard{}
	for _, c := range ch.GetControllerCards() {
		if c.GetSerialNumber() == ccSerial {
			return c.GetOwnershipVoucher(), nil
		}
	}
	return "", status.Errorf(codes.NotFound, "could not find Controller with serial#: %s belonging to chassis %s", ccSerial, chassis.SerialNumber)
}

// AddControlCard adds a new control card to the entity manager.
func (m *InMemoryEntityManager) AddControlCard(serial string) *InMemoryEntityManager {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.controlCardStatuses[serial] = bootz.ControlCardState_CONTROL_CARD_STATUS_UNSPECIFIED
	log.Infof("Added control card %v to server entity manager", serial)
	return m
}

// AddChassis adds a new chassis to the entity manager.
func (m *InMemoryEntityManager) AddChassis(bootMode bootz.BootMode, manufacturer string, serial string) *InMemoryEntityManager {
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

// New returns a new in-memory entity manager.
func New(chassisConfigFile string) (*InMemoryEntityManager, error) {
	newManager := &InMemoryEntityManager{
		chassisInventory:    map[service.EntityLookup]*epb.Chassis{},
		controlCardStatuses: map[string]bootz.ControlCardState_ControlCardStatus{},
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
