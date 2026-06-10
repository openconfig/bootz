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

// Bootz server reference implementation.
//
// The bootz server will provide a simple file based bootstrap
// implementation for devices. The service can be extended by
// providing your own implementation of artifact manager and chassis manager.
package main

import (
	"flag"
	"os"

	"github.com/openconfig/bootz/dhcp"
	"github.com/openconfig/bootz/http"
	"github.com/openconfig/bootz/server"
	"google.golang.org/protobuf/encoding/prototext"

	log "github.com/golang/glog"

	dpb "github.com/openconfig/bootz/dhcp/proto/dhcpconfig"
	cpb "github.com/openconfig/bootz/server/proto/config"
)

var (
	configFile  = flag.String("config_file", "../../testdata/bootz_config.textproto", "Bootz config file.")
	dhcpFile    = flag.String("dhcp_file", "", "DHCP config file.")
	httpAddress = flag.String("http_address", "", "HTTP server address.")
	httpFolder  = flag.String("http_folder", "", "HTTP serving folder.")
)

func main() {
	flag.Parse()

	configBytes, err := os.ReadFile(*configFile)
	if err != nil {
		log.Exitf("failed to read Bootz config file: %v. Specify with argument '--config_file path/to/file'", err)
	}
	config := &cpb.Config{}
	if err := prototext.Unmarshal(configBytes, config); err != nil {
		log.Exitf("failed to unmarshal Bootz config file: %v", err)
	}
	if config.GetServerAddress() == "" {
		log.Exit("no server address found in Bootz config file.")
	}

	var opts []server.Opts

	if *dhcpFile != "" {
		dhcpBytes, err := os.ReadFile(*dhcpFile)
		if err != nil {
			log.Exitf("failed to read DHCP config file: %v. Specify with argument '--dhcp_file path/to/file'", err)
		}
		dhcpConfig := &dpb.Config{}
		if err := prototext.Unmarshal(dhcpBytes, dhcpConfig); err != nil {
			log.Exitf("failed to unmarshal DHCP config file: %v", err)
		}
		opts = append(opts, &dhcp.Opts{
			Config: dhcpConfig,
		})
	}

	if *httpAddress != "" && *httpFolder != "" {
		opts = append(opts, &http.Opts{
			Address: *httpAddress,
			Folder:  *httpFolder,
		})
	}

	log.Infof("=============================================================================")
	log.Infof("=========================== BootZ Server Emulator ===========================")
	log.Infof("=============================================================================")

	s, err := server.NewServer(config, opts...)
	if err != nil {
		log.Exit(err)
	}

	if err := s.Start(); err != nil {
		log.Exit(err)
	}
}
