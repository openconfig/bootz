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

// Bootz client reference implementation.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"time"

	log "github.com/golang/glog"
	ownercertificate "github.com/openconfig/bootz/common/owner_certificate"
	ownershipvoucher "github.com/openconfig/bootz/common/ownership_voucher"
	"github.com/openconfig/bootz/common/signature"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"

	bpb "github.com/openconfig/bootz/proto/bootz"
)

// Describes a modular chassis with two control cards.
const defaultChassisDescriptor = `
manufacturer: 'Cisco' 
part_number: '123'
control_cards { 
	serial_number: '123A' 
	slot: 1 
	part_number: '123A' 
} 
control_cards { 
	serial_number: '123B' 
	slot: 2 
	part_number: '123B'
}
`

// Represents a 128 bit nonce.
const nonceLength = 16

var (
	verifyTLSCert     = flag.Bool("verify_tls_cert", false, "Whether to verify the TLS certificate presented by the Bootz server. If false, all TLS connections are implicitly trusted.")
	insecureBoot      = flag.Bool("insecure_boot", false, "Whether to start the emulated device in non-secure mode. This informs Bootz server to not provide ownership certificates or vouchers.")
	port              = flag.String("port", "15006", "The port to connect to on localhost for the bootz server.")
	chassisDescriptor = flag.String("chassis_descriptor", defaultChassisDescriptor, "A textproto formatting of the ChassisDescriptor message.")
	urlImageMap       = map[string]string{
		"https://path/to/image": "../testdata/image.txt",
	}
)

// validateArtifacts checks the signed artifacts in a GetBootstrapDataResponse. Specifically, it:
// - Checks that the OV in the response is signed by the manufacturer.
// - Checks that the serial number in the OV matches the one in the original request.
// - Verifies that the Ownership Certificate is in the chain of signers of the Pinned Domain Cert.
func validateArtifacts(serialNumber string, resp *bpb.GetBootstrapDataResponse) error {
	// Normally, clients should unmarshal the OV CMS struct and verify that it has been signed by a trusted CA.
	// E.g.:
	// certPool := x509.NewCertPool()
	// certPool.AddCert(vendorCA)
	// parsedOV, err := ownershipvoucher.Unmarshal(resp.GetOwnershipVoucher(), certPool)
	// In this emulator, we don't have a static Vendor Certificate Authority so we unmarshal without
	// verifying.
	parsedOV, err := ownershipvoucher.Unmarshal(resp.GetOwnershipVoucher(), nil)
	if err != nil {
		return fmt.Errorf("unable to verify ownership voucher: %v", err)
	}
	log.Infof("=============================================================================")
	log.Infof("Validated ownership voucher signed by vendor")
	log.Infof("=============================================================================")

	// Verify the serial number for this OV
	log.Infof("Verifying the serial number for this OV")
	if parsedOV.OV.SerialNumber != serialNumber {
		return fmt.Errorf("serial number from OV does not match request")
	}
	log.Infof("Verified serial number is %v", serialNumber)

	// Create a new pool with this PDC.
	log.Infof("Creating a new pool with the PDC")
	pdc, err := x509.ParseCertificate(parsedOV.OV.PinnedDomainCert)
	if err != nil {
		return fmt.Errorf("unable to parse PDC DER to x509 certificate: %v", err)
	}
	pdcPool := x509.NewCertPool()
	pdcPool.AddCert(pdc)

	// Parse the Ownership Certificate.
	log.Infof("Parsing the OC")
	ocCert, err := ownercertificate.Verify(resp.GetOwnershipCertificate(), pdcPool)
	if err != nil {
		return err
	}
	log.Infof("Validated ownership certificate with OV PDC")

	// Validate the response signature.
	log.Infof("=============================================================================")
	log.Infof("===================== Validating the response signature =====================")
	log.Infof("=============================================================================")
	if err := signature.Verify(ocCert, resp.GetSerializedBootstrapData(), resp.GetResponseSignature()); err != nil {
		return err
	}
	log.Infof("Successfully validated the response")
	return nil
}

// validateImage validates if the hash of the downloaded OS image matches the received image hash.
func validateImage(image []byte, softwareImage *bpb.SoftwareImage) error {
	log.Info("Start to validate the downloaded image")
	var hashed [32]byte
	if softwareImage.GetHashAlgorithm() == "SHA256" {
		hashed = sha256.Sum256(image)
	} else {
		return fmt.Errorf("unknown hash algorithm: %q", softwareImage.GetHashAlgorithm())
	}

	receivedHashed, err := hex.DecodeString(softwareImage.GetOsImageHash())
	if err != nil {
		return fmt.Errorf("can not decode received hashed image to bytes, received hash: %q", softwareImage.GetOsImageHash())
	}
	if !bytes.Equal(hashed[:], receivedHashed) {
		return fmt.Errorf("unmatched hash, recevived: %v, downloaded: %v, received hex string: %v, downloaded hex string: %v", receivedHashed, hashed[:], softwareImage.OsImageHash, hex.EncodeToString(hashed[:]))
	}
	log.Info("Verified image hash")
	return nil
}

// downloadImage downloads image from the given URL.
// This is a mock implementation.
func downloadImage(url string) ([]byte, error) {
	log.Infof("Start to download image from %q", url)
	path := urlImageMap[url]

	f, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("can not download image: %v", err)
	}
	log.Infof("Image is successfully downloaded, content length: %v", len(f))
	return f, nil
}

// generateNonce() generates a fixed-length nonce.
func generateNonce() (string, error) {
	b := make([]byte, nonceLength)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func validateChassisDescriptor(chassis *bpb.ChassisDescriptor) {
	if chassis.GetManufacturer() == "" || chassis.GetPartNumber() == "" {
		log.Exitf("Chassis validation error: chassis %v does not have required fields", chassis)
	}
	populatedSlots := make(map[int32]bool)
	if len(chassis.GetControlCards()) > 0 {
		for _, cc := range chassis.GetControlCards() {
			slotPopulated := populatedSlots[cc.GetSlot()]
			if slotPopulated {
				log.Exitf("Chassis validation error: slot %d already populated by another control card", cc.GetSlot())
			}
			populatedSlots[cc.GetSlot()] = true
			if cc.GetPartNumber() == "" || cc.GetSerialNumber() == "" {
				log.Exitf("Chassis validation error: control card %v does not have required fields: %v", cc)
			}
		}
		return
	}
	if chassis.GetSerialNumber() == "" {
		log.Exitf("Chassis validation error: fixed form factor chassis does not contain serial number: %v", chassis)
	}
}

func main() {
	ctx := context.Background()
	flag.Parse()
	log.Infof("=============================================================================")
	log.Infof("=========================== BootZ Client Emulator ===========================")
	log.Infof("=============================================================================")

	log.Infof("=============================================================================")
	log.Infof("================== Constructing a fake device for testing ===================")
	log.Infof("=============================================================================")
	// Construct the fake device.
	chassis := &bpb.ChassisDescriptor{}
	err := prototext.Unmarshal([]byte(*chassisDescriptor), chassis)
	if err != nil {
		log.Exitf("Error un-marshalling chassis descriptor %s: %v", *chassisDescriptor, err)
	}
	validateChassisDescriptor(chassis)
	controlCardState := &bpb.ControlCardState{
		Status: bpb.ControlCardState_CONTROL_CARD_STATUS_NOT_INITIALIZED,
	}
	if len(chassis.GetControlCards()) > 0 {
		// For this implementation, we pick the first control card as the active one. On a real device, the active control
		// card should set its own serial number here.
		controlCardState.SerialNumber = chassis.GetControlCards()[0].GetSerialNumber()
		log.Infof("%v modular chassis with %d control cards starting with SecureOnly = %v", chassis.Manufacturer, len(chassis.GetControlCards()), !*insecureBoot)
	} else {
		controlCardState.SerialNumber = chassis.GetSerialNumber()
		log.Infof("%v fixed form factor chassis %v starting with SecureOnly = %v", chassis.Manufacturer, chassis.SerialNumber, !*insecureBoot)
	}
	log.Infof("Active control card is %v", controlCardState.GetSerialNumber())

	// 1. DHCP Discovery of Bootstrap Server
	// This step emulates the retrieval of the bootz server IP
	// address from a DHCP server. In this case we always connect to localhost.
	log.Infof("=============================================================================")
	log.Infof("================ Starting DHCP discovery of bootstrap server ================")
	log.Infof("=============================================================================")
	if *port == "" {
		log.Exitf("No port provided.")
	}
	bootzAddress := fmt.Sprintf("localhost:%v", *port)
	log.Infof("Connecting to bootz server at address %q", bootzAddress)

	// 2. Bootstrapping Service
	// Device initiates a TLS-secured gRPC connection with the Bootz server.
	tlsConfig := &tls.Config{InsecureSkipVerify: !*verifyTLSCert}
	conn, err := grpc.Dial(bootzAddress, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		log.Exitf("Client unable to connect to Bootstrap Server: %v", err)
	}
	defer conn.Close()
	log.Infof("Creating a new bootstrap client")
	c := bpb.NewBootstrapClient(conn)
	log.Infof("Client connected to bootz server")

	log.Infof("=============================================================================")

	nonce := ""
	if !*insecureBoot {
		log.Infof("Device in secure boot mode, generating a nonce that the Bootz server will use to sign the response")
		// Generate a nonce that the Bootz server will use to sign the response.
		nonce, err = generateNonce()
		if err != nil {
			log.Exitf("Error generating nonce: %v", err)
		}
		log.Infof("Nonce of %v generated successfully", nonce)
	}

	log.Infof("=============================================================================")
	log.Infof("======================== Retrieving bootstrap data ==========================")
	log.Infof("=============================================================================")
	log.Infof("Building bootstrap data request")

	req := &bpb.GetBootstrapDataRequest{
		ChassisDescriptor: chassis,
		ControlCardState:  controlCardState,
		Nonce:             nonce,
	}
	log.Infof("Built bootstrap data request with %v chassis %v and control card %v with status %v and nonce %v",
		req.ChassisDescriptor.Manufacturer, req.ChassisDescriptor.SerialNumber, req.ControlCardState.SerialNumber, req.ControlCardState.Status, req.Nonce)

	// Get bootstrapping data from Bootz server
	// TODO: Extract and parse response.
	log.Infof("Requesting Bootstrap Data from Bootz server")
	resp, err := c.GetBootstrapData(ctx, req)
	if err != nil {
		log.Exitf("Error calling GetBootstrapData: %v", err)
	}
	log.Infof("Successfully retrieved Bootstrap Data from server")

	// Only check OC, OV and response signature if SecureOnly is set.
	if !*insecureBoot {
		log.Infof("=============================================================================")
		log.Infof("====================== Validating response signature ========================")
		log.Infof("=============================================================================")
		if err := validateArtifacts(controlCardState.GetSerialNumber(), resp); err != nil {
			log.Exitf("Error validating signed data: %v", err)
		}
	}

	var signedResp bpb.BootstrapDataSigned
	if err := proto.Unmarshal(resp.GetSerializedBootstrapData(), &signedResp); err != nil {
		log.Exitf("unable to unmarshal serialized bootstrap data: %v", err)
	}

	if !*insecureBoot && signedResp.GetNonce() != nonce {
		log.Exitf("GetBootstrapDataResponse nonce does not match")
	}

	// TODO: Verify the hash of the intended image.
	// Simply print out the received configs we get. This section should actually contain the logic to verify and install the images and config.
	log.Infof("=============================================================================")
	log.Infof("===================== Processing control card configs =======================")
	log.Infof("=============================================================================")
	if len(signedResp.GetResponses()) == 0 {
		log.Exitf("response contained no bootstrap responses")
	}
	for _, data := range signedResp.GetResponses() {
		log.Infof("Received config for control card %v", data.GetSerialNum())
		log.Infof("Start to download and validate image, received: %+v...", data.GetIntendedImage())
		image, err := downloadImage(data.GetIntendedImage().GetUrl())
		if err != nil {
			log.Exitf("unable to download image (url: %q): %v", data.GetIntendedImage().GetUrl(), err)
		}
		err = validateImage(image, data.GetIntendedImage())
		if err != nil {
			log.Exitf("Error validating intended image: %v", err)
		}
		time.Sleep(time.Second * 5)
		log.Infof("Done")
		log.Infof("Installing boot config %+v...", data.GetBootConfig())
		time.Sleep(time.Second * 5)
		log.Infof("Done")
		log.Infof("=============================================================================")
	}

	// Reconnect to the server with the provided server_trust_cert.
	log.Infof("Re-establishing TLS connection with server using provided trust cert")
	trustCert := signedResp.GetResponses()[0].GetServerTrustCert()
	if trustCert == "" {
		log.Exitf("server did not provide a server trust certificate")
	}
	// Decode the trust cert
	trustCertDecoded, err := base64.StdEncoding.DecodeString(trustCert)
	if err != nil {
		log.Exitf("unable to base64-decode trust cert")
	}
	trustAnchor, err := x509.ParseCertificate(trustCertDecoded)
	if err != nil {
		log.Exitf("unable to parse server trust certificate")
	}

	trustCertPool := x509.NewCertPool()
	trustCertPool.AddCert(trustAnchor)

	tlsConfig = &tls.Config{
		InsecureSkipVerify: false,
		RootCAs:            trustCertPool,
	}
	conn.Close()
	conn, err = grpc.Dial(bootzAddress, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		log.Exitf("Client unable to re-connect to Bootstrap Server: %v", err)
	}
	c = bpb.NewBootstrapClient(conn)
	log.Infof("Reconnected to server with fully trusted TLS")

	// 6. ReportProgress
	log.Infof("=========================== Sending Status Report ===========================")
	log.Infof("=============================================================================")
	statusReq := &bpb.ReportStatusRequest{
		Status:        bpb.ReportStatusRequest_BOOTSTRAP_STATUS_SUCCESS,
		StatusMessage: "Bootstrap Success",
		States: []*bpb.ControlCardState{
			{
				Status:       bpb.ControlCardState_CONTROL_CARD_STATUS_INITIALIZED,
				SerialNumber: chassis.GetControlCards()[0].GetSerialNumber(),
			},
			{
				Status:       bpb.ControlCardState_CONTROL_CARD_STATUS_INITIALIZED,
				SerialNumber: chassis.GetControlCards()[1].GetSerialNumber(),
			},
		},
	}

	_, err = c.ReportStatus(ctx, statusReq)
	if err != nil {
		log.Exitf("Error reporting status: %v", err)
	}
	log.Infof("Status report sent")
	// At this point the device has minimal configuration and can receive further gRPC calls. After this, the TPM Enrollment and attestation occurs.
}
