// Copyright 2026 Google LLC
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

// Package runner contains the integration test runner for the Bootz SUT.
package runner

import (
	"context"
	"fmt"
	"testing"
	"time"

	"flag"
	log "github.com/golang/glog"
	"google.golang.org/protobuf/encoding/prototext"
	"github.com/openconfig/gnoigo/factoryreset"
	"github.com/openconfig/gnoigo"
	"github.com/openconfig/monax"
	"github.com/openconfig/monax/monaxondatratest"
	"github.com/openconfig/monax/runtime/kubernetesruntime"
	"github.com/openconfig/ondatra/binding"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/openconfig/ondatra"

	bootzpb "github.com/openconfig/bootz/proto/bootz"
	pbgrpc "github.com/openconfig/bootz/server/tests/proto/sut"
	pb "github.com/openconfig/bootz/server/tests/proto/sut"
	dpb "github.com/openconfig/bootz/server/tests/proto/test"
)

const (
	bootzTimeout = 1 * time.Hour
)

var (
	config       monax.Config
	sut          *monax.SUT
	params       *dpb.TestParameters
	macAddresses []string
)

func fetchMACAddresses(t *testing.T, dut *ondatra.DUTDevice) []string {
	t.Helper()
	var macAddresses []string
	for _, intf := range params.GetInterfaceInfo().GetManagementInterfaceNames() {
		val, ok := gnmi.Lookup(t, dut, gnmi.OC().Interface(intf).Ethernet().MacAddress(
).State()).Val()
		if ok && val != "" {
			macAddresses = append(macAddresses, val)
		}
	}
	if len(macAddresses) == 0 {
		t.Fatalf("Failed to find any MAC addresses for DUT %s", dut.ID())
	}
	return macAddresses
}

func dhcpService(ctx context.Context, t *testing.T) pbgrpc.DHCPServiceClient {
	t.Helper()
	dhcpServiceConn, err := sut.Interfaces().GRPC(ctx, "bootz.DHCPService")
	if err != nil {
		t.Fatalf("Failed to get DHCPService connection: %v", err)
	}
	return pbgrpc.NewDHCPServiceClient(dhcpServiceConn)
}

func controllerService(ctx context.Context, t *testing.T) pbgrpc.BootzControllerClient {
	t.Helper()
	controllerServiceConn, err := sut.Interfaces().GRPC(ctx, "bootz.BootzController")
	if err != nil {
		t.Fatalf("Failed to get BootzController connection: %v", err)
	}
	return pbgrpc.NewBootzControllerClient(controllerServiceConn)
}

func imageService(ctx context.Context, t *testing.T) pbgrpc.ImageServiceClient {
	t.Helper()
	imageServiceConn, err := sut.Interfaces().GRPC(ctx, "bootz.ImageService")
	if err != nil {
		t.Fatalf("Failed to get ImageService connection: %v", err)
	}
	return pbgrpc.NewImageServiceClient(imageServiceConn)
}

func init() {
	config.RegisterFlags(nil)
}

// Init initializes the Bootz Monax test.
func Init(ctx context.Context, m *testing.M, newBindFn func() (binding.Binding, error)) error {
	if !flag.Parsed() {
		flag.Parse()
	}
	newRuntimeFn := kubernetesruntime.New

	var err error
	sut, err = monaxondatratest.Init(ctx, &config, newRuntimeFn)
	if err != nil {
		log.ErrorContextf(ctx, "Failed to initialize SUT: %v", err)
		return fmt.Errorf("failed to initialize SUT: %w", err)
	}
	if newBindFn == nil {
		// If no binding function is provided, pass nil to let Ondatra use its globally
		// registered binding, which is the standard way Ondatra runs when a binding
		// package is imported anonymously (e.g. `import _ "github.com/myorg/ondatrabin
d"`).
		ondatra.RunTests(m, nil)
	} else {
		ondatra.RunTests(m, newBindFn)
	}
	return nil
}

func parseBootzParameters(p *dpb.TestParameters) error {
	if p == nil {
		return fmt.Errorf("Bootz parameters are required")
	}
	if p.GetInterfaceInfo() == nil {
		return fmt.Errorf("interface_info is required")
	}
	if p.GetInterfaceInfo().GetDhcpAddress() == "" {
		return fmt.Errorf("dhcp_address is required")
	}
	if p.GetInterfaceInfo().GetDefaultGateway() == "" {
		return fmt.Errorf("default_gateway is required")
	}
	if p.GetInterfaceInfo().GetMaskLength() == 0 {
		return fmt.Errorf("mask_length is required")
	}
	if p.GetOsImage() == nil {
		return fmt.Errorf("os_image is required")
	}
	if p.GetOsImage().GetName() == "" {
		return fmt.Errorf("os_image name is required")
	}
	if p.GetOsImage().GetVersion() == "" {
		return fmt.Errorf("os_image version is required")
	}
	if p.GetOsImage().GetDownloadUri() == "" {
		return fmt.Errorf("os_image download_uri is required")
	}
	if len(p.GetInterfaceInfo().GetManagementInterfaceNames()) == 0 {
		return fmt.Errorf("At least one management interface name is required")
	}
	if p.GetBootstrapData() == nil {
		return fmt.Errorf("bootstrap_data is required")
	}
	params = p
	return nil
}

func waitForBootz(t *testing.T, stream pbgrpc.BootzController_SubscribeClient) error {
	t.Helper()
	for {
		message, err := stream.Recv()
		if err != nil {
			return err
		}
		t.Logf("Received message from Bootz controller:\n%v", prototext.Format(message)
)
		if message.GetError() != "" {
			return fmt.Errorf("Bootz controller returned an error to the DUT: %v", 
message.GetError())
		}
		if message.GetReportStatusRequest() != nil {
			switch message.GetReportStatusRequest().GetStatus() {
			case bootzpb.ReportStatusRequest_BOOTSTRAP_STATUS_SUCCESS:
				t.Logf("Received BOOTSTRAP_STATUS_SUCCESS from DUT")
				return nil
			case bootzpb.ReportStatusRequest_BOOTSTRAP_STATUS_FAILURE:
				return fmt.Errorf("Received BOOTSTRAP_STATUS_FAILURE from DUT: 
%v", message.GetReportStatusRequest().GetStatusMessage())
			}
		}
	}
}

func attemptGNOIFactoryReset(ctx context.Context, t *testing.T, dut *ondatra.DUTDevice) error {
	t.Helper()
	var err error
	for i := 0; i < 3; i++ {
		err = func() error {
			attemptCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
			defer cancel()

			c, err := dut.RawAPIs().BindingDUT().DialGNOI(attemptCtx)
			if err != nil {
				return fmt.Errorf("failed to dial gNOI: %v", err)
			}
			op := factoryreset.NewStartOperation().ZeroFill(false).FactoryOS(false)
			_, err = gnoigo.Execute(attemptCtx, c, op)
			if err != nil {
				return fmt.Errorf("failed to execute gNOI factory reset: %v", e
rr)
			}
			return nil
		}()
		if err == nil {
			t.Logf("Successfully factory reset DUT over gNOI")
			return nil
		}
		t.Logf("Attempt %d to factory reset over gNOI failed: %v", i+1, err)
		if i < 2 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(10 * time.Second):
			}
		}
	}
	return fmt.Errorf("failed to factory reset DUT over gNOI after 3 attempts: last error %
v", err)
}



func fetchDUT(t *testing.T) *ondatra.DUTDevice {
	t.Helper()
	duts := ondatra.DUTs(t)
	if len(duts) != 1 {
		t.Fatalf("expected exactly 1 DUT, got %d", len(duts))
	}
	for _, dut := range duts {
		return dut
	}
	t.Fatalf("internal error: Failed to find DUT")
	return nil
}

// Run executes the Bootz test.
func Run(t *testing.T, parameters *dpb.TestParameters) {
	t.Helper()
	ctx := t.Context()
	if err := parseBootzParameters(parameters); err != nil {
		t.Fatalf("Failed to parse bootz parameters: %v", err)
	}
	if err := sut.Status(ctx); err != nil {
		t.Fatalf("SUT is unhealthy: %v", err)
	}
	t.Logf("Getting DUT info")
	dut := fetchDUT(t)
	t.Logf("Found DUT with ID: %q", dut.ID())
	macAddresses = fetchMACAddresses(t, dut)
	t.Logf("Found DUT MAC addresses: %v", macAddresses)

	waitCtx, cancel := context.WithTimeout(ctx, bootzTimeout)
	defer cancel()

	// 1. Prepare the OS image in the Image Service.
	imageService := imageService(waitCtx, t)
	uploadReq := &pb.UploadRequest{
		Image: params.GetOsImage(),
	}
	uploadResp, err := imageService.Upload(waitCtx, uploadReq)
	if err != nil {
		t.Fatalf("Failed to upload image to Image Server: %v", err)
	}
	t.Logf("Upload() response:\n%v", prototext.Format(uploadResp))

	// 2. Set Bootstrap Data and Security Artifacts for the DUT.
	controllerService := controllerService(waitCtx, t)
	
	setBootReq := &pb.SetBootstrapDataRequest{
		BootstrapData: params.GetBootstrapData(),
	}
	if _, err := controllerService.SetBootstrapData(waitCtx, setBootReq); err != nil {
		t.Fatalf("Failed to set Bootstrap data: %v", err)
	}
	t.Logf("Set Bootstrap data for DUT")

	if params.GetSecurityArtifacts() != nil {
		setSecReq := &pb.SetSecurityArtifactsRequest{
			SecurityArtifacts: params.GetSecurityArtifacts(),
		}
		if _, err := controllerService.SetSecurityArtifacts(waitCtx, setSecReq); err !=
 nil {
			t.Fatalf("Failed to set Security Artifacts: %v", err)
		}
		t.Logf("Set Security Artifacts for DUT")
	}

	if params.GetRecoveryData() != nil {
		setRecReq := &pb.SetRecoveryDataRequest{
			RecoveryData: params.GetRecoveryData(),
		}
		if _, err := controllerService.SetRecoveryData(waitCtx, setRecReq); err != nil 
{
			t.Fatalf("Failed to set Recovery Data: %v", err)
		}
		t.Logf("Set Recovery Data for DUT")
	}

	// 3. Discover the Bootz URL.
	bootzURLResp, err := controllerService.GetBootzURL(waitCtx, &pb.GetBootzURLRequest{})
	if err != nil {
		t.Fatalf("Failed to get Bootz URL: %v", err)
	}
	t.Logf("GetBootzURL() response:\n%v", prototext.Format(bootzURLResp))

	// 4. Create the DHCP lease.
	dhcpService := dhcpService(waitCtx, t)
	createLeaseReq := &pb.CreateLeaseRequest{
		BootzServerAddress: bootzURLResp.GetBootzUrl(),
		IpAddress:          params.GetInterfaceInfo().GetDhcpAddress(),
		MacAddresses:       macAddresses,
		MaskLen:            params.GetInterfaceInfo().GetMaskLength(),
		Gateway:            params.GetInterfaceInfo().GetDefaultGateway(),
	}
	if _, err := dhcpService.CreateLease(waitCtx, createLeaseReq); err != nil {
		t.Fatalf("Failed to create DHCP lease: %v", err)
	}
	t.Logf("Created DHCP lease for MAC addresses: %v", macAddresses)

	// 5. Factory Reset the DUT.
	if err := attemptGNOIFactoryReset(waitCtx, t, dut); err != nil {
		t.Logf("Failed to factory reset DUT over gNOI: %v", err)
		t.Logf("Assuming DUT is in ZTP loop and continuing with Bootz")
	}

	// 6. Start listening for Bootz status reports.
	stream, err := controllerService.Subscribe(waitCtx, &pb.SubscribeRequest{})
	if err != nil {
		t.Fatalf("Failed to subscribe to Bootz status reports: %v", err)
	}

	t.Logf("Listening for Bootz status reports from DUT")

	errChan := make(chan error, 1)
	go func() {
		errChan <- waitForBootz(t, stream)
	}()

	select {
	case err := <-errChan:
		if err != nil {
			t.Fatalf("Bootz failed: %v", err)
		}
		t.Logf("Bootz succeeded for DUT %s", dut.ID())
	case <-waitCtx.Done():
		t.Fatalf("Bootz timed out after %v", bootzTimeout)
	}
}

