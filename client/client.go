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
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	log "github.com/golang/glog"
	ownercertificate "github.com/openconfig/bootz/common/owner_certificate"
	ownershipvoucher "github.com/openconfig/bootz/common/ownership_voucher"
	"github.com/openconfig/bootz/common/signature"
	"github.com/openconfig/bootz/server/artifactmanager"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"

	bpb "github.com/openconfig/bootz/proto/bootz"
	cpb "github.com/openconfig/bootz/server/proto/config"
)

var (
	configFile   = flag.String("config_file", "../testdata/bootz_config.textproto", "Bootz config file.")
	streaming    = flag.Bool("streaming", false, "Whether to use the streaming bootstrap RPC.")
	insecureBoot = flag.Bool("insecure_boot", false, "Whether to start the emulated device in non-secure mode. This informs Bootz server to not provide ownership certificates or vouchers.")

	urlImageMap = map[string]string{"http://127.0.0.1/path/to/image": "../testdata/image.bin"}

	idevid = &tls.Certificate{}
)

func validateChassis(chassis *cpb.Chassis) {
	if chassis.GetManufacturer() == "" {
		log.Exitf("Chassis validation error: chassis %v does not have manufacturer", chassis)
	}
	if len(chassis.GetControlCards()) == 0 {
		log.Exitf("Chassis validation error: chassis %v does not have control cards", chassis)
	}
	for _, cc := range chassis.GetControlCards() {
		if cc.GetSerialNumber() == "" {
			log.Exitf("Chassis validation error: control card %v does not have serial number", cc)
		}
		if cc.GetIdevid() == nil {
			log.Exitf("Chassis validation error: control card %v does not have IDevID", cc)
		}
	}
}

// validateArtifacts checks the Ownership Voucher, Owner Certificate, and Bootstrap Data Signature.
// Specifically, it:
// - Checks that the OV is signed by the manufacturer.
// - Checks that the serial number in the OV matches the one in the original request.
// - Verifies that the Owner Certificate is in the chain of signers of the Pinned Domain Cert.
// - Verifies the signature over the bootstrap data.
func validateArtifacts(serialNumber string, ov, oc, data []byte, sigString string) error {
	// Normally, clients should unmarshal the OV CMS struct and verify that it has been signed by a trusted CA.
	// E.g.:
	// certPool := x509.NewCertPool()
	// certPool.AddCert(vendorCA)
	// parsedOV, err := ownershipvoucher.Unmarshal(ov, certPool)
	// In this emulator, we don't have a static Vendor Certificate Authority so we unmarshal without verifying.
	parsedOV, err := ownershipvoucher.Unmarshal(ov, nil)
	if err != nil {
		return fmt.Errorf("unable to verify ownership voucher: %v", err)
	}
	log.Infof("Validated ownership voucher signed by vendor")

	// Validate the serial number for this OV
	if parsedOV.OV.SerialNumber != serialNumber {
		return fmt.Errorf("serial number from OV does not match request")
	}
	log.Infof("Validated serial number: %q", serialNumber)

	// Create a new pool with this PDC.
	log.Infof("Creating a new pool with the PDC")
	pdc, err := x509.ParseCertificate(parsedOV.OV.PinnedDomainCert)
	if err != nil {
		return fmt.Errorf("unable to parse PDC DER to x509 certificate: %v", err)
	}
	pdcPool := x509.NewCertPool()
	pdcPool.AddCert(pdc)

	// Parse the Owner Certificate.
	log.Infof("Parsing the OC")
	ocCert, err := ownercertificate.Verify(oc, pdcPool)
	if err != nil {
		return err
	}
	log.Infof("Validated owner certificate with OV PDC")

	sig, err := base64.StdEncoding.DecodeString(sigString)
	if err != nil {
		return fmt.Errorf("unable to base64 decode signature: %v", err)
	}
	if err := signature.Verify(ocCert, data, sig); err != nil {
		return err
	}
	log.Infof("Validated response signature")

	log.Infof("=============================================================================")
	log.Infof("===================== Successfully validated bootstrap data =================")
	log.Infof("=============================================================================")
	return nil
}

// validateImage validates if the hash of the downloaded OS image matches the received image hash.
func validateImage(image []byte, softwareImage *bpb.SoftwareImage) error {
	var hashed [32]byte
	if softwareImage.GetHashAlgorithm() == "ietf-sztp-conveyed-info:sha-256" {
		hashed = sha256.Sum256(image)
	} else {
		return fmt.Errorf("unknown hash algorithm: %q", softwareImage.GetHashAlgorithm())
	}

	// The hash string from the server may contain colons, which need to be removed.
	receivedHashed, err := hex.DecodeString(strings.ReplaceAll(softwareImage.GetOsImageHash(), ":", ""))
	if err != nil {
		return fmt.Errorf("can not decode received hashed image to bytes, received hash: %q", softwareImage.GetOsImageHash())
	}
	if !bytes.Equal(hashed[:], receivedHashed) {
		return fmt.Errorf("unmatched hash, received: %x, downloaded: %x", receivedHashed, hashed[:])
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

// handleStream handles the streaming bootstrap workflow.
func handleStream(ctx context.Context, c bpb.BootstrapClient, msg proto.Message) (*bpb.StreamBootstrapDataResponse, []byte, error) {
	log.Info("Starting a new stream...")
	stream, err := c.BootstrapStreamV1(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to start bootstrap stream: %v", err)
	}

	identity := &bpb.Identity{
		Type: &bpb.Identity_IdevidCert{
			IdevidCert: base64.StdEncoding.EncodeToString(idevid.Certificate[0]),
		},
	}
	var request *bpb.BootstrapStreamRequestV1
	var response *bpb.BootstrapStreamResponseV1
	switch m := msg.(type) {
	case *bpb.GetBootstrapDataRequest:
		m.Identity = identity
		request = &bpb.BootstrapStreamRequestV1{
			Type: &bpb.BootstrapStreamRequestV1_BootstrapRequest{
				BootstrapRequest: m,
			},
		}
	case *bpb.ReportStatusRequest:
		m.Identity = identity
		request = &bpb.BootstrapStreamRequestV1{
			Type: &bpb.BootstrapStreamRequestV1_ReportStatusRequest{
				ReportStatusRequest: m,
			},
		}
	default:
		return nil, nil, fmt.Errorf("unexpected message type: %T", msg)
	}

	// Send initial request
	if err = stream.Send(request); err != nil {
		return nil, nil, fmt.Errorf("failed to send initial request: %v", err)
	}
	// Receive challenge
	if response, err = stream.Recv(); err != nil {
		return nil, nil, fmt.Errorf("failed to receive initial response: %v", err)
	}
	log.Infof("=============================================================================")
	log.Infof("======================== Received challenge =================================")
	log.Infof("=============================================================================")

	challenge := response.GetChallengeRequest()
	if challenge == nil {
		return nil, nil, fmt.Errorf("expected a challenge, but got %v", response)
	}
	nonce := challenge.GetTpm20Idevid().GetNonce()
	if len(nonce) == 0 {
		return nil, nil, fmt.Errorf("challenge is missing nonce")
	}
	hpkeKey, err := hpke.DHKEM(ecdh.X25519()).GenerateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate HPKE key: %v", err)
	}
	transportKey := &bpb.TransportKey{
		CipherSuite: bpb.HPKECipherSuite_HPKE_CIPHER_SUITE_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM,
		PublicKey:   hpkeKey.PublicKey().Bytes(),
		Nonce:       nonce,
	}
	serializedMsg, err := proto.Marshal(transportKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to serialize transport key message: %v", err)
	}
	sig, err := signature.Sign(idevid.PrivateKey, idevid.Leaf.SignatureAlgorithm, serializedMsg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign transport key: %v", err)
	}
	request = &bpb.BootstrapStreamRequestV1{
		Type: &bpb.BootstrapStreamRequestV1_ChallengeResponse_{
			ChallengeResponse: &bpb.BootstrapStreamRequestV1_ChallengeResponse{
				Type: &bpb.BootstrapStreamRequestV1_ChallengeResponse_Tpm20Idevid{
					Tpm20Idevid: &bpb.BootstrapStreamRequestV1_ChallengeResponse_ChallengeResponseTPM20IDevID{
						SerializedTransportKey: serializedMsg,
						Signature:              sig,
					},
				},
			},
		},
	}

	log.Infof("=============================================================================")
	log.Infof("======================== Sending challenge response =========================")
	log.Infof("=============================================================================")
	// Send challenge response
	if err = stream.Send(request); err != nil {
		return nil, nil, fmt.Errorf("failed to send second request: %v", err)
	}
	// Receive bootstrap data or reposrt status ack
	if response, err = stream.Recv(); err != nil {
		return nil, nil, fmt.Errorf("failed to receive second response: %v", err)
	}

	var ret *bpb.StreamBootstrapDataResponse
	var dataDecrypted []byte
	switch msg.(type) {
	case *bpb.GetBootstrapDataRequest:
		ret = response.GetBootstrapResponse()
		if ret == nil {
			return nil, nil, fmt.Errorf("expected stream bootstrap data response, but got %v", response)
		}
		recipient, err := hpke.NewRecipient(ret.GetEncapsulatedKey(), hpkeKey, hpke.HKDFSHA256(), hpke.AES256GCM(), nil)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create HPKE recipient: %v", err)
		}
		dataDecrypted, err = recipient.Open(nil, ret.GetEncryptedSerializedBootstrapData())
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decrypt bootstrap data: %v", err)
		}
	case *bpb.ReportStatusRequest:
		if response.GetReportStatusResponse() == nil {
			return nil, nil, fmt.Errorf("expected report status response, but got %v", response)
		}
	default:
		return nil, nil, fmt.Errorf("unexpected message type: %T", msg)
	}

	stream.CloseSend()
	_, err = stream.Recv()
	if err != io.EOF {
		return nil, nil, fmt.Errorf("expected EOF after final response, got %v", err)
	}

	return ret, dataDecrypted, nil
}

// reconnectWithTrustCert re-establishes the gRPC connection with the server using the provided trust certificate.
func reconnectWithTrustCert(bootzAddress string, signedResp *bpb.BootstrapDataSigned) (*grpc.ClientConn, bpb.BootstrapClient, error) {
	log.Infof("Re-establishing TLS connection with server using provided trust cert")
	if len(signedResp.GetResponses()) == 0 {
		return nil, nil, fmt.Errorf("response contained no bootstrap responses")
	}
	trustCert := signedResp.GetResponses()[0].GetServerTrustCert()
	if trustCert == "" {
		return nil, nil, fmt.Errorf("server did not provide a server trust certificate")
	}
	// Decode the trust cert
	trustCertDecoded, err := base64.StdEncoding.DecodeString(trustCert)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to base64-decode trust cert: %v", err)
	}
	trustAnchor, err := x509.ParseCertificate(trustCertDecoded)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse server trust certificate: %v", err)
	}

	trustCertPool := x509.NewCertPool()
	trustCertPool.AddCert(trustAnchor)

	tlsConfig := &tls.Config{
		// The client must verify the Bootz server cert for any new connection after the server_trust_cert from Bootstrap Data is obtained.
		InsecureSkipVerify: false,
		RootCAs:            trustCertPool,
	}
	// For Unary Bootz, the device must present IDevID cert during TLS handshake.
	if !*streaming {
		tlsConfig.Certificates = []tls.Certificate{*idevid}
	}
	newConn, err := grpc.Dial(bootzAddress, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		return nil, nil, fmt.Errorf("client unable to re-connect to Bootstrap Server: %v", err)
	}
	newC := bpb.NewBootstrapClient(newConn)
	log.Infof("Reconnected to server with fully trusted TLS")
	return newConn, newC, nil
}

// processControlCardConfigs handles the downloading and installation of boot configurations.
func processControlCardConfigs(signedResp *bpb.BootstrapDataSigned) {
	// Simply print out the received configs we get. This section should actually contain the logic to verify and install the images and config.
	log.Infof("=============================================================================")
	log.Infof("===================== Processing control card configs =======================")
	log.Infof("=============================================================================")
	if len(signedResp.GetResponses()) == 0 {
		log.Exitf("response contained no bootstrap responses")
	}
	for _, data := range signedResp.GetResponses() {
		log.Infof("Received config for control card %v", data.GetSerialNum())
		log.Infof("Start to download and validate image: %+v", data.GetIntendedImage())
		image, err := downloadImage(data.GetIntendedImage().GetUrl())
		if err != nil {
			log.Exitf("Unable to download image (url: %q): %v", data.GetIntendedImage().GetUrl(), err)
		}
		err = validateImage(image, data.GetIntendedImage())
		if err != nil {
			log.Exitf("Error validating intended image: %v", err)
		}
		log.Infof("Sleep 5 seconds to emulate image upgrade")
		time.Sleep(time.Second * 5)
		log.Infof("Installing boot config %+v...", data.GetBootConfig())
		log.Infof("Sleep 5 seconds to emulate boot config installation")
		time.Sleep(time.Second * 5)
		log.Infof("=============================================================================")
	}
}

func main() {
	ctx := context.Background()
	flag.Parse()
	configBytes, err := os.ReadFile(*configFile)
	if err != nil {
		log.Exit("Failed to read config file. Specify with argument '--config_file path/to/file'")
	}
	config := &cpb.Config{}
	if err := prototext.Unmarshal(configBytes, config); err != nil {
		log.Exitf("Failed to unmarshal config file: %v", err)
	}
	bootzAddress := config.GetServerAddress()
	if bootzAddress == "" {
		log.Exit("Bootz server address not found in config file.")
	}
	log.Infof("=============================================================================")
	log.Infof("=========================== BootZ Client Emulator ===========================")
	log.Infof("=============================================================================")

	log.Infof("Use Streaming Bootz RPC: %v", *streaming)

	log.Infof("=============================================================================")
	log.Infof("================== Constructing a fake device for testing ===================")
	log.Infof("=============================================================================")
	if len(config.GetChassis()) == 0 {
		log.Exit("Chassis not found in config file.")
	}
	// Construct a fake device from the first chassis found in the config file.
	chassis := config.GetChassis()[0]
	validateChassis(chassis)
	// For this implementation, we pick the first control card as the active one. On a real device, the bootstrap request can initiate from any control card.
	card := chassis.GetControlCards()[0]
	serial := card.GetSerialNumber()
	chassisDescriptor := &bpb.ChassisDescriptor{
		Manufacturer: chassis.GetManufacturer(),
	}
	if len(chassis.GetControlCards()) > 1 {
		log.Infof("Constructing a modular form factor chassis")
		for _, v := range chassis.GetControlCards() {
			chassisDescriptor.ControlCards = append(chassisDescriptor.GetControlCards(), &bpb.ControlCard{
				SerialNumber: v.GetSerialNumber(),
			})
		}
	} else {
		log.Infof("Constructing a fixed form factor chassis")
		chassisDescriptor.SerialNumber = serial
	}
	controlCardState := &bpb.ControlCardState{
		Status:       bpb.ControlCardState_CONTROL_CARD_STATUS_NOT_INITIALIZED,
		SerialNumber: serial,
	}
	log.Infof("Active control card is %q", serial)
	idevidCert, idevidKey, err := artifactmanager.ParseCertKeyPair(card.GetIdevid())
	if err != nil {
		log.Exitf("Error parsing active control card IDevID: %v", err)
	}
	idevid = &tls.Certificate{
		Certificate: [][]byte{idevidCert.Raw},
		PrivateKey:  idevidKey,
		Leaf:        idevidCert,
	}

	// DHCP Discovery of Bootstrap Server
	// This step retrieves the Bootz server IP address from a DHCP server.
	// For this implementation, we skip this step.
	log.Infof("=============================================================================")
	log.Infof("================ Starting DHCP discovery of bootstrap server ================")
	log.Infof("=============================================================================")

	// Device initiates a TLS-secured gRPC connection with the Bootz server.
	// For the initial BootstrapRequest, the client should not verify the Bootz server cert.
	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	// For Unary Bootz, the device must present IDevID cert during TLS handshake.
	if !*streaming {
		tlsConfig.Certificates = []tls.Certificate{*idevid}
	}
	log.Infof("Connecting to bootz server at address %q", bootzAddress)
	conn, err := grpc.Dial(bootzAddress, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		log.Exitf("Client unable to connect to Bootstrap Server: %v", err)
	}
	defer conn.Close()
	log.Infof("Creating a new bootstrap client")
	c := bpb.NewBootstrapClient(conn)
	log.Infof("=============================================================================")
	log.Infof("======================== Client connected to Bootz server ===================")
	log.Infof("=============================================================================")

	nonce := ""
	if !*insecureBoot {
		log.Infof("Device in secure boot mode, generating a client nonce")
		nonceBytes := make([]byte, 32)
		if _, err := rand.Read(nonceBytes); err != nil {
			log.Exitf("Error generating nonce: %v", err)
		}
		nonce = base64.StdEncoding.EncodeToString(nonceBytes)
		log.Infof("Nonce generated successfully: %q", nonce)
	}

	log.Infof("=============================================================================")
	log.Infof("======================== Requesting bootstrap data ==========================")
	log.Infof("=============================================================================")

	req := &bpb.GetBootstrapDataRequest{
		ChassisDescriptor: chassisDescriptor,
		ControlCardState:  controlCardState,
		Nonce:             nonce,
	}
	log.Infof("Sending bootstrap data request: %+v", req)

	var ov, oc, data, dataDecrypted []byte
	var sig string
	if *streaming {
		resp, serializedData, err := handleStream(ctx, c, req)
		if err != nil {
			log.Exitf("Error calling handleStream: %v", err)
		}
		ov = resp.GetOwnershipVoucher()
		oc = resp.GetOwnershipCertificate()
		data = resp.GetEncryptedSerializedBootstrapData()
		sig = resp.GetResponseSignature()
		dataDecrypted = serializedData

	} else {
		resp, err := c.GetBootstrapData(ctx, req)
		if err != nil {
			log.Exitf("Error calling GetBootstrapData: %v", err)
		}
		ov = resp.GetOwnershipVoucher()
		oc = resp.GetOwnershipCertificate()
		data = resp.GetSerializedBootstrapData()
		sig = resp.GetResponseSignature()
		dataDecrypted = data
	}

	log.Infof("=============================================================================")
	log.Infof("======================== Received bootstrap data ============================")
	log.Infof("=============================================================================")

	// Only check OC, OV and response signature if SecureOnly is set.
	if !*insecureBoot {
		if err := validateArtifacts(controlCardState.GetSerialNumber(), ov, oc, data, sig); err != nil {
			log.Exitf("Error validating signed bootstrap data: %v", err)
		}
	}

	var signedResp bpb.BootstrapDataSigned
	if err := proto.Unmarshal(dataDecrypted, &signedResp); err != nil {
		log.Exitf("Error unmarshalling serialized bootstrap data: %v", err)
	}

	if !*insecureBoot && signedResp.GetNonce() != nonce {
		log.Exitf("GetBootstrapDataResponse nonce does not match")
	}

	// Usually the device may go through one or several rounds of reboot to apply the image and the bootstrap config,
	// causing the RPC connection to break.
	// We emulate this reboot by closing the connection and create a new connection for status report.
	conn.Close()

	// Apply image and bootstrap config.
	processControlCardConfigs(&signedResp)

	// Reconnect to the server with the provided server_trust_cert.
	conn, c, err = reconnectWithTrustCert(bootzAddress, &signedResp)
	if err != nil {
		log.Exitf("Error reconnecting to server: %v", err)
	}

	log.Infof("=============================================================================")
	log.Infof("=========================== Sending Status Report ===========================")
	log.Infof("=============================================================================")

	statusReq := &bpb.ReportStatusRequest{
		Status:        bpb.ReportStatusRequest_BOOTSTRAP_STATUS_SUCCESS,
		StatusMessage: "Bootstrap Success",
	}
	if len(chassisDescriptor.GetControlCards()) > 0 {
		for _, cc := range chassisDescriptor.GetControlCards() {
			statusReq.States = append(statusReq.GetStates(), &bpb.ControlCardState{
				Status:       bpb.ControlCardState_CONTROL_CARD_STATUS_INITIALIZED,
				SerialNumber: cc.GetSerialNumber(),
			})
		}
	} else {
		statusReq.States = []*bpb.ControlCardState{
			{
				Status:       bpb.ControlCardState_CONTROL_CARD_STATUS_INITIALIZED,
				SerialNumber: chassisDescriptor.GetSerialNumber(),
			},
		}
	}

	if *streaming {
		if _, _, err = handleStream(ctx, c, statusReq); err != nil {
			log.Exitf("Error calling handleStream: %v", err)
		}
	} else {
		if _, err = c.ReportStatus(ctx, statusReq); err != nil {
			log.Exitf("Error reporting status: %v", err)
		}
	}
	log.Infof("Status report sent and acknowledged")

	// At this point the device has minimal configuration and can receive further gRPC calls. After this, the TPM Enrollment and attestation occurs.
	log.Infof("=============================================================================")
	log.Infof("Bootstrap (mode: streaming=%v) finished successfully", *streaming)
	log.Infof("=============================================================================")
}
