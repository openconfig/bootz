// Bootz server reference implementation.
//
// The bootz server will provide a simple file based bootstrap
// implementation for devices.  The service can be extended by
// provding your own implementation of the entity manager.
package main

import (
	"flag"
	"fmt"
	"net"

	"github.com/openconfig/bootz/proto/bootz"
	"github.com/openconfig/bootz/server/service"
	"google.golang.org/grpc"

	log "github.com/golang/glog"
)

var (
	port = flag.String("port", "15000", "The port to start the Bootz server on localhost")
)

func main() {
	flag.Parse()
	// TODO: Implement an entity manager.
	c := service.New(nil)
	s := grpc.NewServer()

	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%v", *port))
	if err != nil {
		log.Exitf("Error listening on port: %v", err)
	}
	bootz.RegisterBootstrapServer(s, c)
	err = s.Serve(lis)
	if err != nil {
		log.Exitf("Error serving grpc: %v", err)
	}
}
