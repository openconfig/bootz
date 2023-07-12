// Bootz server reference implementation.
//
// The bootz server will provide a simple file based bootstrap
// implementation for devices.  The service can be extended by
// provding your own implementation of the entity manager.
package main

import (
	"github.com/labstack/gommon/log"
	"github.com/openconfig/bootz/proto/bootz"
	"github.com/openconfig/bootz/server/service"
	"google.golang.org/grpc"
)

var (
	port = pflags.StringVar("")
)

func main() {
	em := &fileentitymanager.Manager{}
	c, err := service.New(em)
	s := grpc.NewServer()
	s.RegisterService(bootz.BootstrapServer, c)
	if err != nil {
		log.Errorf("Failed to start server: %w", err)
	}
	if err := c.Start(); err != nil {
		log.Fatalf("Server exited: %w", err)
	}
}
