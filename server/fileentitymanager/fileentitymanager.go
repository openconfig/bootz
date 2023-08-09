package fileentitymanager

import (
	//"context"

	"github.com/openconfig/bootz/proto/bootz"
	"github.com/openconfig/bootz/server/service"

	//"github.com/openconfig/gnmi/errlist"
	//"google.golang.org/grpc/codes"
	//"google.golang.org/grpc/status"
)

type manager struct {
	cfgFile string
} 


func (*manager) ResolveChassis(service.EntityLookup) (service.ChassisEntity, error) {
	return service.ChassisEntity{}, nil

}
func (*manager)	GetBootstrapData(bootz.ControlCard) (bootz.BootstrapDataResponse, error){
	return bootz.BootstrapDataResponse{}, nil
}
func (*manager) SetStatus(service.EntityLookup, bootz.ReportStatusRequest) error {
	return nil
}
func (*manager) Sign(resp *bootz.BootstrapDataResponse) error {
	return nil
}

func New(entityFiles string) service.EntityManager{
	return &manager{}
	// reed and populate entities from the config file
}






