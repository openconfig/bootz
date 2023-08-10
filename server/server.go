// Bootz server reference implementation.
//
// The bootz server will provide a simple file based bootstrap
// implementation for devices.  The service can be extended by
// provding your own implementation of the entity manager.
package main

import (
	"flag"
	"net"
	"fmt"

	"github.com/labstack/gommon/log"
	"github.com/openconfig/bootz/proto/bootz"
	"github.com/openconfig/bootz/server/service"
	"github.com/openconfig/bootz/server/fileentitymanager"
	"google.golang.org/grpc"
)

var (
	address = flag.String("address", "127.0.0.1:8999", "The address where the bootzserver will listen")
)

func main() {
	em := fileentitymanager.New("config_file+test")
	lis, err := net.Listen("tcp", *address)
	if err != nil {
		panic(fmt.Sprintf("failed to listen: %v", err))
	}
	bootzService:=service.New(em); 
	grpcSrv := grpc.NewServer()
	grpcSrv.RegisterService(&bootz.Bootstrap_ServiceDesc, bootzService)
	go func() {
		err:=grpcSrv.Serve(lis); if err != nil {
			log.Errorf("Failed to start server: %w", err)
		}
	}()
	//grpcSrv.GracefulStop()

}
