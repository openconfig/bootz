package main

import (
	"flag"
	"testing"
)

// TestStartup tests that a gRPC server can be created with the default flags.
func TestStartup(t *testing.T) {
	flag.Parse()
	s, err := newServer()
	if err != nil {
		t.Fatalf("newServer() err = %v, want nil", err)
	}
	go func() {
		err = s.Start()
		if err != nil {
			t.Errorf("Error serving grpc: %v", err)
		}
	}()
	s.Stop()
}
