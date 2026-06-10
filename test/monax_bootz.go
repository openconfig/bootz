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

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	log "github.com/golang/glog"
	"github.com/openconfig/monax"
	"github.com/openconfig/monax/monaxtest"
	"github.com/openconfig/monax/runtime/kubernetesruntime"
)

var (
	config monax.Config
	sut    *monax.SUT
)

func init() {
	flag.StringVar(&config.AbstractSUTPath, "abstract_sut", "./sut/abstract_sut.txtpb", "Path to the Monax abstract SUT file")
	flag.StringVar(&config.LibraryPath, "library", "./sut/kubernetes_library.txtpb", "Path to the Monax library file")
	flag.StringVar(&config.RuntimeParametersPath, "runtime_parameters", "./sut/kubernetes_runtime_parameters.txtpb", "Path to the Monax runtime parameters file")
}

func main() {
	flag.Parse()
	defer log.Flush() // Ensures log files are written to.

	fmt.Println("=========================================================================")
	fmt.Println("Building the SUTs (Bootz, HTTP)... This may take a few minutes.")
	fmt.Println("=========================================================================")

	var err error
	ctx := context.Background()
	sut, err = monaxtest.Start(ctx, &config, kubernetesruntime.New)
	if err != nil {
		log.ExitContextf(ctx, "Failed to start SUT: %v", err)
	}
	defer func() {
		if err := sut.Stop(ctx); err != nil {
			log.ErrorContextf(ctx, "Failed to stop SUT: %v", err)
		}
	}()

	fmt.Println("=========================================================================")
	fmt.Println("The SUTs (Bootz, HTTP) are now ready and running in Monax containers.")
	fmt.Println("=========================================================================")
	fmt.Println(">>> To test DHCP Bootz: <<<")
	fmt.Println("1. Make sure DHCP service is running on bare metal in another terminal.")
	fmt.Println("2. Put your chassis into DHCP Bootz ZeroTouch mode to start the testing.")
	fmt.Println("-------------------------------------------------------------------------")
	fmt.Println(">>> To test DHCP-less Bootz: <<<")
	fmt.Println("1. Run the DHCP-less Bootz commands on your chassis to start the testing.")
	fmt.Println("=========================================================================")
	fmt.Println("After you finish the testing, press Ctrl+C to stop the SUTs.")
	fmt.Println("=========================================================================")

	sigchan := make(chan os.Signal, 1)
	signal.Notify(sigchan, os.Interrupt)
	<-sigchan
}
