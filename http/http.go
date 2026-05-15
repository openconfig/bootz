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

// Package http implements an HTTP server for devices to download image file from.
package http

import (
	"fmt"
	"net/http"
	"os"
	"sync"

	log "github.com/golang/glog"
)

// Config contains the http server configuration.
type Config struct {
	Address string
	Folder  string
}

type Server struct {
	server *http.Server
}

var instance *Server = nil
var lock = &sync.Mutex{}

// Start starts the http server with the given configuration.
func Start(conf *Config) error {
	lock.Lock()
	defer lock.Unlock()

	if instance != nil {
		return fmt.Errorf("http server already started")
	}

	if conf.Folder == "" {
		return fmt.Errorf("serving folder not specified")
	}
	if _, err := os.ReadDir(conf.Folder); err != nil {
		return fmt.Errorf("folder is not accessible: %v", err)
	}

	fs := http.FileServer(http.Dir(conf.Folder))
	mux := http.NewServeMux()
	mux.Handle("/", fs)
	srv := &http.Server{Addr: conf.Address, Handler: mux}
	instance = &Server{server: srv}

	go func() {
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			log.Exitf("Error starting http server: %v", err)
		}
	}()

	log.Infof("Serving http at address %q for folder %q", conf.Address, conf.Folder)

	return nil
}

// Stop stops the http server.
func Stop() {
	lock.Lock()
	defer lock.Unlock()

	if instance != nil {
		instance.server.Close()
	}
	instance = nil
}
