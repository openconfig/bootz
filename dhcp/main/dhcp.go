// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package main provides the main function for running the DHCP server.
package main

import (
	"flag"
	"os"
	"os/signal"

	log "github.com/golang/glog"
	"github.com/openconfig/bootz/dhcp"
	"google.golang.org/protobuf/encoding/prototext"

	cpb "github.com/openconfig/bootz/dhcp/proto/config"
)

var (
	configFile = flag.String("config_file", "../../testdata/dhcp_config.textproto", "DHCP config file.")
)

func main() {
	flag.Parse()

	configBytes, err := os.ReadFile(*configFile)
	if err != nil {
		log.Exit("failed to read config file. Specify with argument '--config_file path/to/file'")
	}
	config := &cpb.Config{}
	if err := prototext.Unmarshal(configBytes, config); err != nil {
		log.Exitf("failed to unmarshal config file: %v", err)
	}
	if config.GetInterface() == "" {
		log.Exit("no interface specified in config file")
	}

	go func() {
		sigchan := make(chan os.Signal, 1)
		signal.Notify(sigchan, os.Interrupt)
		<-sigchan
		dhcp.Stop()
		os.Exit(0)
	}()

	if err := dhcp.Start(config); err != nil {
		log.Exitf("error starting dhcp server: %v", err)
	}

	select {}
}
