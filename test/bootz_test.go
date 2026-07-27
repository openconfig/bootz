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

//go:build !ci
// +build !ci

// Package test implements fully automatic Monax Bootz test.
package test

import (
	"context"
	"crypto/tls"
	"flag"
	"os"
	"os/signal"
	"testing"
	"time"

	log "github.com/golang/glog"
	"github.com/openconfig/bootz/test/dut"
	"github.com/openconfig/monax"
	"github.com/openconfig/monax/monaxtest"
	"github.com/openconfig/monax/runtime/kubernetesruntime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	bpb "github.com/openconfig/bootz/proto/bootz"
	tpb "github.com/openconfig/bootz/proto/test"
)

var (
	dhcp = flag.Bool("dhcp", false, "Test DHCP Bootz (true) or DHCP-less Bootz (false)")

	config monax.Config
)

func init() {
	flag.StringVar(&config.AbstractSUTPath, "abstract_sut", "./sut/abstract_sut.txtpb", "Path to the Monax abstract SUT file")
	flag.StringVar(&config.LibraryPath, "library", "./sut/kubernetes_library.txtpb", "Path to the Monax library file")
	flag.StringVar(&config.RuntimeParametersPath, "runtime_parameters", "./sut/kubernetes_runtime_parameters.txtpb", "Path to the Monax runtime parameters file")
}

func TestBootz(t *testing.T) {
	flag.Parse()
	defer log.Flush() // Ensures log files are written to.

	log.Infof("=========================================================================")
	log.Infof("Building the SUTs (Bootz, HTTP)... This may take a few minutes.")
	log.Infof("=========================================================================")

	ctx := context.Background()
	sut, err := monaxtest.Start(ctx, &config, kubernetesruntime.New)
	if err != nil {
		t.Fatalf("Failed to start SUT: %v", err)
	}
	defer func() {
		if err := sut.Stop(ctx); err != nil {
			t.Fatalf("Failed to stop SUT: %v", err)
		}
	}()

	if err := sut.Status(ctx); err != nil {
		t.Fatalf("SUT is unhealthy: %v", err)
	}

	log.Infof("=========================================================================")
	log.Infof("The SUTs (Bootz, HTTP) are now ready and running in Monax containers.")
	log.Infof("=========================================================================")

	time.Sleep(time.Second * 1)

	// Start the Bootz process on the DUT.
	if err := dut.StartBootz(*dhcp); err != nil {
		t.Fatalf("Failed to start Bootz on DUT: %v", err)
	}

	conn, err := sut.Interfaces().GRPC(ctx, "bootz.Test", grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})))
	if err != nil {
		t.Fatalf("Failed to get Bootz connection: %v", err)
	}
	testClient := tpb.NewTestClient(conn)

	log.Infof("=========================================================================")
	log.Infof("Waiting for the DUT to report bootstrap status......")
	log.Infof("=========================================================================")

	stream, err := testClient.Subscribe(ctx, &tpb.SubscribeRequest{})
	if err != nil {
		t.Fatalf("Failed to subscribe to Bootz: %v", err)
	}

	errChan := make(chan error, 1)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)

	go func() {
		response, err := stream.Recv() // This call is blocking until the response is available.
		if err != nil {
			errChan <- err
			return
		}

		log.Infof("=========================================================================")
		log.Infof("Received ReportStatusRequest from the DUT:")
		log.Infof("%+v", response)
		log.Infof("=========================================================================")

		if response.GetStatus() != bpb.ReportStatusRequest_BOOTSTRAP_STATUS_SUCCESS {
			t.Errorf("Bootz test failed, expected %v, got %v", bpb.ReportStatusRequest_BOOTSTRAP_STATUS_SUCCESS, response.GetStatus())
		}
		for _, ccs := range response.GetStates() {
			if ccs.GetStatus() != bpb.ControlCardState_CONTROL_CARD_STATUS_INITIALIZED {
				t.Errorf("Bootz test failed for control card %q, expected %v, got %v", ccs.GetSerialNumber(), bpb.ControlCardState_CONTROL_CARD_STATUS_INITIALIZED, ccs.GetStatus())
			}
		}

		errChan <- err
	}()

	// Make sure proper cleanup if the test is interrupted by Ctrl+C.
	select {
	case err := <-errChan:
		if err != nil {
			t.Fatalf("Subscribe stream exited with error: %v", err)
		} else {
			log.Info("Subscribe stream completed successfully")
		}
	case <-sigChan:
		t.Fatal("Test interrupted prematurely by Ctrl+C! Performing clean up...")
	}
}
