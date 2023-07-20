package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"

	log "github.com/golang/glog"

	"github.com/openconfig/bootz/proto/bootz"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Represents a 128 bit nonce.
const nonceLength = 16

var (
	bootMode = flag.String("boot_mode", "SecureOnly", "The BootMode the device can start in.")
	port     = flag.String("port", "", "The port to listen to on localhost for the bootz server.")
)

// generateNonce() generates a fixed-length nonce.
func generateNonce() (string, error) {
	b := make([]byte, nonceLength)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func main() {
	ctx := context.Background()
	flag.Parse()

	secureOnly := *bootMode == "SecureOnly"

	// Construct the fake device.
	// TODO: Allow these values to be set e.g. via a flag.
	chassis := bootz.ChassisDescriptor{
		Manufacturer: "Cisco",
		SerialNumber: "123",
		ControlCards: []*bootz.ControlCard{
			{
				SerialNumber: "123A",
				Slot:         1,
				PartNumber:   "123A",
			},
			{
				SerialNumber: "123B",
				Slot:         2,
				PartNumber:   "123B",
			},
		},
	}

	log.Infof("%v chassis %v starting in %v boot mode", chassis.Manufacturer, chassis.SerialNumber, *bootMode)

	// 1. DHCP Discovery of Bootstrap Server
	// This step emulates the retrieval of the bootz server IP
	// address from a DHCP server. In this case we always connect to localhost.

	if *port == "" {
		log.Exitf("No port provided.")
	}
	bootzAddress := fmt.Sprintf("localhost:%v", *port)
	log.Infof("Connecting to bootz server at address %q", bootzAddress)

	// 2. Bootstrapping Service
	// Device initiates a TLS-secured gRPC connection with the Bootz server.
	// TODO: Make this use TLS.
	conn, err := grpc.Dial(bootzAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Exitf("Unable to connect to Bootstrap Server: %v", err)
	}
	defer conn.Close()
	c := bootz.NewBootstrapClient(conn)
	log.Infof("Connected to bootz server")

	nonce := ""
	if secureOnly {
		// Generate a nonce that the Bootz server will use to sign the response.
		nonce, err = generateNonce()
		if err != nil {
			log.Exitf("Error generating nonce: %v", err)
		}
	}

	req := &bootz.GetBootstrapDataRequest{
		ChassisDescriptor: &chassis,
		// This is the active control card, e.g. the one making the bootz request.
		ControlCardState: &bootz.ControlCardState{
			SerialNumber: chassis.ControlCards[0].GetSerialNumber(),
			Status:       bootz.ControlCardState_CONTROL_CARD_STATUS_NOT_INITIALIZED,
		},
		Nonce: nonce,
	}

	// Get bootstrapping data from Bootz server
	// TODO: Extract and parse response.
	log.Infof("Requesting Bootstrap Data from Bootz server")
	resp, err := c.GetBootstrapData(ctx, req)
	if err != nil {
		log.Exitf("Error calling GetBootstrapData: %v", err)
	}

	// Only check OC, OV and response signature if SecureOnly is set.
	if secureOnly {
		ov := resp.GetOwnershipVoucher()
		if len(ov) == 0 {
			log.Exitf("Received empty ownership voucher from server")
		}
		log.Infof("Verified Ownership Voucher")

		oc := resp.GetOwnershipCertificate()
		if len(oc) == 0 {
			log.Exitf("Received empty ownership certificate from server")
		}
		log.Infof("Verified Ownership Certificate")
		signature := resp.GetResponseSignature()
		if signature == "" {
			log.Exitf("Received empty response signature from server")
		}
		log.Infof("Verified Response Signature")
	}

	signedResp := resp.GetSignedResponse()
	if secureOnly && signedResp.GetNonce() != nonce {
		log.Exitf("GetBootstrapDataResponse nonce does not match")
	}

	for _, data := range signedResp.GetResponses() {
		log.Infof("Received config for control card %v", data.GetSerialNum())
		log.Infof("Downloading image %+v", data.GetIntendedImage())
		log.Infof("Using boot config %+v", data.GetBootConfig())
	}

	// 6. ReportProgress
	log.Infof("Sending Status Report")
	statusReq := &bootz.ReportStatusRequest{
		Status:        bootz.ReportStatusRequest_BOOTSTRAP_STATUS_SUCCESS,
		StatusMessage: "Bootstrap Success",
		States: []*bootz.ControlCardState{
			{
				Status:       bootz.ControlCardState_CONTROL_CARD_STATUS_INITIALIZED,
				SerialNumber: chassis.GetControlCards()[0].GetSerialNumber(),
			},
			{
				Status:       bootz.ControlCardState_CONTROL_CARD_STATUS_INITIALIZED,
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
