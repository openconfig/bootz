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

var port = flag.String("port", "", "The port to listen to on localhost for the bootz server.")

// nonce() generates a fixed-length nonce.
func nonce() (string, error) {
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
	// 1. DHCP Discovery of Bootstrap Server
	// This step emulates the retrieval of the bootz server IP
	// address from a DHCP server. In this case we always connect to localhost.

	if *port == "" {
		log.Exitf("No port provided.")
	}

	// 2. Bootstrapping Service
	// Device initiates a TLS-secured gRPC connection with the Bootz server.
	// TODO: Make this use TLS.
	conn, err := grpc.Dial(fmt.Sprintf("localhost:%v", *port), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Exitf("Unable to connect to Bootstrap Server: %v", err)
	}
	defer conn.Close()
	c := bootz.NewBootstrapClient(conn)

	// Generate a nonce that the Bootz served will use to sign the response.
	nonce, err := nonce()
	if err != nil {
		log.Exitf("Error generating nonce: %v", err)
	}

	// TODO: Build or store the fields of this request programatically.
	// This represents a simple dual-control card chassis manufactured by Cisco.
	// In this case, the bootz request is initiated by the control card in slot 1.
	req := &bootz.GetBootstrapDataRequest{
		ChassisDescriptor: &bootz.ChassisDescriptor{
			Manufacturer: "Cisco",
			ControlCards: []*bootz.ControlCard{
				{
					PartNumber:   "1",
					SerialNumber: "ABC123",
					Slot:         1,
				},
				{
					PartNumber:   "2",
					SerialNumber: "ABC124",
					Slot:         2,
				},
			},
		},
		// This is the active control card, e.g. the one making the bootz request.
		ControlCardState: &bootz.ControlCardState{
			SerialNumber: "ABC123",
			Status:       bootz.ControlCardState_CONTROL_CARD_STATUS_NOT_INITIALIZED,
		},
		Nonce: nonce,
	}

	// Get bootstrapping data from Bootz server
	// TODO: Extract and parse response.
	_, err = c.GetBootstrapData(ctx, req)
	if err != nil {
		log.Exitf("Error calling GetBootstrapData: %v", err)
	}

	// 6. ReportProgress
	statusReq := &bootz.ReportStatusRequest{
		Status:        bootz.ReportStatusRequest_BOOTSTRAP_STATUS_SUCCESS,
		StatusMessage: "Bootstrap Success",
		States: []*bootz.ControlCardState{
			{
				Status:       bootz.ControlCardState_CONTROL_CARD_STATUS_INITIALIZED,
				SerialNumber: "ABC123",
			},
			{
				Status:       bootz.ControlCardState_CONTROL_CARD_STATUS_INITIALIZED,
				SerialNumber: "ABC124",
			},
		},
	}

	_, err = c.ReportStatus(ctx, statusReq)
	if err != nil {
		log.Exitf("Error reporting status: %v", err)
	}

	// At this point the device has minimal configuration and can receive further gRPC calls. After this, the TPM Enrollment and attestation occurs.

}
