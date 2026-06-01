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

package monax_integration

import (
	"context"
	"testing"
	"time"

	"flag"

	log "github.com/golang/glog"
	"github.com/openconfig/monax"
	"github.com/openconfig/monax/monaxtest"
	"github.com/openconfig/monax/runtime/kubernetesruntime"

	pbgrpc "github.com/openconfig/bootz/server/tests/proto/sut"
)

var (
	config monax.Config
	sut    *monax.SUT
)

func init() {
	config.RegisterFlags(nil)
}

func TestMain(m *testing.M) {
	ctx := context.Background()

	flag.Parse()
	defer log.Flush()
	if testing.Short() {
		log.WarningContext(ctx, "Skipping SUT test in short mode")
		return
	}

	newRuntimeFn := kubernetesruntime.New

	var err error
	// Start the SUT (system under test) components only. This is independent of Ondatra an
d
	// does not require a testbed or binding.
	sut, err = monaxtest.Start(ctx, &config, newRuntimeFn)
	if err != nil {
		log.ExitContextf(ctx, "Failed to start SUT: %v", err)
	}
	defer func() {
		if err := sut.Stop(ctx); err != nil {
			log.ErrorContextf(ctx, "Failed to stop SUT: %v", err)
		}
	}()

	m.Run()
}

func TestSUTConnectivity(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	if err := sut.Status(ctx); err != nil {
		t.Fatalf("SUT is unhealthy: %v", err)
	}

	// 1. Dial and verify DHCP SUT service
	t.Run("DHCP Service", func(t *testing.T) {
		dhcpConn, err := sut.Interfaces().GRPC(ctx, "bootz.DHCPService")
		if err != nil {
			t.Fatalf("Failed to connect to SUT DHCPService: %v", err)
		}
		dhcpClient := pbgrpc.NewDHCPServiceClient(dhcpConn)
		t.Logf("Successfully established gRPC channel to SUT DHCPService: %v", dhcpClie
nt)
	})

	// 2. Dial and verify Image SUT service
	t.Run("Image Service", func(t *testing.T) {
		imageConn, err := sut.Interfaces().GRPC(ctx, "bootz.ImageService")
		if err != nil {
			t.Fatalf("Failed to connect to SUT ImageService: %v", err)
		}
		imageClient := pbgrpc.NewImageServiceClient(imageConn)
		t.Logf("Successfully established gRPC channel to SUT ImageService: %v", imageCl
ient)
	})

	// 3. Dial and verify BootzController SUT service
	t.Run("BootzController Service", func(t *testing.T) {
		controllerConn, err := sut.Interfaces().GRPC(ctx, "bootz.BootzController")
		if err != nil {
			t.Fatalf("Failed to connect to SUT BootzController: %v", err)
		}
		controllerClient := pbgrpc.NewBootzControllerClient(controllerConn)
		t.Logf("Successfully established gRPC channel to SUT BootzController: %v", cont
rollerClient)
	})
}