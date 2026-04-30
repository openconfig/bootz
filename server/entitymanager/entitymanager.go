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
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"sync"

	log "github.com/golang/glog"
	ownercertificate "github.com/openconfig/bootz/common/owner_certificate"
	"github.com/openconfig/bootz/common/signature"
	"github.com/openconfig/bootz/common/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"

	tpb "github.com/openconfig/attestz/proto/tpm_enrollz"
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
	chassisInventory []*epb.ChassisInventory
	// represents the current status of known control cards
	controlCardStatuses map[string]bpb.ControlCardState_ControlCardStatus
	// stores the default config such as security artifacts dir.
	defaults *epb.Options
	// security artifacts  (OVs, OC and PDC).
	// TODO: handle mutlti-vendor case
	secArtifacts *types.SecurityArtifacts
	vendorCAPool *x509.CertPool
}

// ResolveChassis fills the chassis information based on the matched inventory.
func (m *InMemoryEntityManager) ResolveChassis(ctx context.Context, chassis *types.Chassis) error {
	inventory, err := m.lookupChassis(chassis.ActiveSerial)
	if err != nil {
		return err
	}
	var key *rsa.PublicKey
	var keyType tpb.Key
	switch chassis.Identity.GetType().(type) {
	case *bpb.Identity_Tpm20EkPub, *bpb.Identity_Tpm20PpkPub, *bpb.Identity_Tpm12EkPub, *bpb.Identity_EkPpkPub:
		for _, c := range inventory.GetControllerCards() {
			if c.GetSerialNumber() == chassis.ActiveSerial {
				block, _ := pem.Decode([]byte(c.GetPublicKey()))
				if block == nil {
					return status.Errorf(codes.InvalidArgument, "failed to decode PEM block from public key: %s", c.GetPublicKey())
				}
				if block.Type != "PUBLIC KEY" {
					return status.Errorf(codes.InvalidArgument, "unsupported public key type: %s", block.Type)
				}
				pub, err := x509.ParsePKIXPublicKey(block.Bytes)
				if err != nil {
					return status.Errorf(codes.InvalidArgument, "failed to parse DER encoded public key: %v", err)
				}
				rsaPub, ok := pub.(*rsa.PublicKey)
				if !ok {
					return status.Errorf(codes.InvalidArgument, "public key is not of type RSA")
				}
				key = rsaPub
				keyType = c.GetPublicKeyType()
				break
			}
		}
		if key == nil || keyType == tpb.Key_KEY_UNSPECIFIED {
			return status.Errorf(codes.Internal, "public key not found")
		}
	}
	bootCfg, err := populateBootConfig(inventory.GetConfig().GetBootConfig())
	if err != nil {
		return err
	}
	authzConf, err := m.populateAuthzConfig(inventory)
	if err != nil {
		return err
	}

	chassis.ActivePublicKey = key
	chassis.ActivePublicKeyType = keyType
	chassis.Hostname = inventory.GetName()
	chassis.BootMode = inventory.GetBootMode()
	chassis.StreamingSupported = inventory.GetStreamingSupported()
	chassis.SoftwareImage = inventory.GetSoftwareImage()
	chassis.BootloaderPasswordHash = inventory.GetBootloaderPasswordHash()
	chassis.Realm = defaultRealm
	chassis.Manufacturer = inventory.GetManufacturer()
	chassis.PartNumber = inventory.GetPartNumber()
	chassis.BootConfig = bootCfg
	chassis.Authz = authzConf
	return nil
}

func (m *InMemoryEntityManager) lookupChassis(serial string) (*epb.ChassisInventory, error) {
	if serial == "" {
		return nil, status.Errorf(codes.InvalidArgument, "lookup serial number can't be empty")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, chassis := range m.chassisInventory {
		// Search for the chassis serial number first.
		if chassis.GetSerialNumber() == serial {
			return chassis, nil
		}
		// While we're here, try looking up by control card.
		for _, c := range chassis.GetControllerCards() {
			if c.GetSerialNumber() == serial {
				return chassis, nil
			}
		}
	}
	return nil, status.Errorf(codes.NotFound, "could not find chassis for lookup serial %+v", serial)
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

func (m *InMemoryEntityManager) populateAuthzConfig(ch *epb.ChassisInventory) (*apb.UploadRequest, error) {
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
func (m *InMemoryEntityManager) GetBootstrapData(ctx context.Context, chassis *types.Chassis, serial string) (*bpb.BootstrapDataResponse, error) {
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

// Sign generates a signature over the input data using its Ownership Certificate private key,
// and returns the based64-encoded signature string, the Ownership Voucher, and the Ownership Certificate.
func (m *InMemoryEntityManager) Sign(ctx context.Context, data []byte, chassis *types.Chassis) (string, []byte, []byte, error) {
	if len(data) == 0 {
		return "", nil, nil, status.Errorf(codes.InvalidArgument, "empty input data to sign")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	// Check if security artifacts are provided for signing.
	if m.secArtifacts == nil {
		return "", nil, nil, status.Errorf(codes.Internal, "security artifact is missing")
	}

	// Fetch the OV
	ov, err := m.fetchOwnershipVoucher(chassis.ActiveSerial)
	if err != nil {
		return "", nil, nil, status.Errorf(codes.NotFound, "failed to fetch ownership voucher: %v", err)
	}
	log.Infof("OV fetched")

	// Fetch the OC
	oc, err := ownercertificate.GenerateCMS(m.secArtifacts.OwnerCert, m.secArtifacts.OwnerCertPrivateKey)
	if err != nil {
		return "", nil, nil, status.Errorf(codes.Internal, "failed to generate ownership certificate: %v", err)
	}
	log.Infof("OC fetched")

	sig, err := signature.Sign(m.secArtifacts.OwnerCertPrivateKey, m.secArtifacts.OwnerCert.SignatureAlgorithm, data)
	if err != nil {
		return "", nil, nil, status.Errorf(codes.Internal, "failed to generate signature: %v", err)
	}
	log.Infof("Signature generated")

	return sig, ov, oc, nil
}

// ValidateIDevID verifies the authenticity and authorization of a device by validating its IDevID certificate.
// The PEM encoded intermediate certificate chain is optional.
func (em *InMemoryEntityManager) ValidateIDevID(ctx context.Context, cert *x509.Certificate, intermediates []byte, chassis *types.Chassis) error {
	opts := x509.VerifyOptions{
		Roots:     em.vendorCAPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	if len(intermediates) > 0 {
		opts.Intermediates = x509.NewCertPool()
		if !opts.Intermediates.AppendCertsFromPEM(intermediates) {
			return fmt.Errorf("failed to parse PEM encoded intermediate certificates: %v", intermediates)
		}
	}
	if _, err := cert.Verify(opts); err != nil {
		return fmt.Errorf("IDevID certificate chain validation failed: %w", err)
	}

	certSerial := getCertSerialNumber(cert.Subject.SerialNumber)

	for _, v := range chassis.Serials {
		if strings.EqualFold(certSerial, v) {
			log.InfoContextf(ctx, "Successfully validated IDevID for chassis %q", certSerial)
			return nil
		}
	}

	return fmt.Errorf("serial number from certificate (%v) does not match chassis (%+v)", certSerial, chassis.Serials)
}

// getCertSerialNumber extracts the serial number from the cert subject serial number.
func getCertSerialNumber(serial string) string {
	// cert.Subject.SerialNumber can come in the format PID:xxxxxxx SN:1234JF or just
	// the serial number as is.
	// Try to extract out the value after SN:
	sn := strings.Split(serial, "SN:")
	if len(sn) != 2 {
		return sn[0]
	}
	return sn[1]
}

// fetchOwnershipVoucher retrieves the ownership voucher for a control card
func (m *InMemoryEntityManager) fetchOwnershipVoucher(ccSerial string) ([]byte, error) {
	ov, ok := m.secArtifacts.OV[ccSerial]
	if !ok {
		return nil, fmt.Errorf("OV not found for serial %v", ccSerial)
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
func (m *InMemoryEntityManager) AddChassis(bootMode bpb.BootMode, manufacturer string, serial string, streamingSupported bool) *InMemoryEntityManager {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.chassisInventory = append(m.chassisInventory, &epb.ChassisInventory{
		Manufacturer:       manufacturer,
		SerialNumber:       serial,
		BootMode:           bootMode,
		StreamingSupported: streamingSupported,
	})
	log.Infof("Added %v chassis %v to server entity manager", manufacturer, serial)
	return m
}

// GetChassisInventory returns the chassis inventory
func (m *InMemoryEntityManager) GetChassisInventory() []*epb.ChassisInventory {
	return m.chassisInventory
}

// New returns a new in-memory entity manager.
func New(chassisConfigFile string, artifacts *types.SecurityArtifacts) (*InMemoryEntityManager, error) {
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
func (m *InMemoryEntityManager) ReplaceDevice(serial string, new *epb.ChassisInventory) error {
	// todo: Validate before replace
	// todo: Forward error from validateConfig

	if serial == "" {
		return status.Error(codes.InvalidArgument, "lookup serial number must be set")
	}

	if new == nil || new.SerialNumber == "" {
		return status.Error(codes.InvalidArgument, "new chassis or serial can not be nil")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	for i, ch := range m.chassisInventory {
		if ch.GetSerialNumber() == serial {
			m.chassisInventory[i] = new
			return nil
		}
	}

	m.chassisInventory = append(m.chassisInventory, new)
	return nil
}

// DeleteDevice removes the chassis at the provided lookup from the entitymanager.
func (m *InMemoryEntityManager) DeleteDevice(serial string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, ch := range m.chassisInventory {
		if ch.GetSerialNumber() == serial {
			m.chassisInventory = append(m.chassisInventory[:i], m.chassisInventory[i+1:]...)
		}
	}
}

// GetDevice returns a copy of the chassis at the provided serial number.
func (m *InMemoryEntityManager) GetDevice(serial string) (*epb.ChassisInventory, error) {
	ch, err := m.lookupChassis(serial)
	if err != nil {
		return nil, err
	}
	return proto.Clone(ch).(*epb.ChassisInventory), nil
}

// GetAll returns a copy of the chassisInventory field.
func (m *InMemoryEntityManager) GetAll() []*epb.ChassisInventory {
	m.mu.Lock()
	defer m.mu.Unlock()

	chassisClone := make([]*epb.ChassisInventory, len(m.chassisInventory))

	for i, chassis := range m.chassisInventory {
		chassisClone[i] = proto.Clone(chassis).(*epb.ChassisInventory)
	}

	return chassisClone
}
