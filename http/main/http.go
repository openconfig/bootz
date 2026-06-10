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

// Package main provides the main function for running the HTTP server.
package main

import (
	"flag"
	"os"
	"os/signal"

	log "github.com/golang/glog"
	"github.com/openconfig/bootz/http"
)

var (
	address = flag.String("address", ":80", "The address 'IP:port' to use for http server. (Defaults to localhost:80)")
	folder  = flag.String("folder", ".", "The local folder to serve files from.")
)

func main() {
	flag.Parse()

	conf := &http.Opts{
		Address: *address,
		Folder:  *folder,
	}

	go func() {
		sigchan := make(chan os.Signal, 1)
		signal.Notify(sigchan, os.Interrupt)
		<-sigchan
		http.Stop()
		os.Exit(0)
	}()

	if err := http.Start(conf); err != nil {
		log.Exitf("error starting http server: %v", err)
	}

	select {}
}
