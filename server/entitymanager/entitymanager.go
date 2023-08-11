package entitymanager

import (
	//"context"
	"fmt"
	"os"
	//"crypto/sha512"

	"github.com/labstack/gommon/log"

	"github.com/openconfig/bootz/proto/bootz"
	epb "github.com/openconfig/bootz/server/entitymanager/proto/entity/entity"

	"github.com/openconfig/bootz/server/service"
	"google.golang.org/protobuf/encoding/prototext"
)

type InMemoryEntityManager struct {
	chassisConfigs []*epb.Chassis  
} 

type bootLog struct {
	BootMode epb.BootModes
	StartTimeStamp uint64
	EndTimeStamp   uint64
	Status []bootz.ReportStatusRequest_BootstrapStatus
	BootResponse *bootz.BootstrapDataResponse
	BootRequest *bootz.GetBootstrapDataRequest
	Err error 
}

func (m *InMemoryEntityManager) ResolveChassis(lookup service.EntityLookup) (*service.ChassisEntity, error) {
	for _,chassic := range m.chassisConfigs {
		// matching on Manufacturer and serial number is the must
		if chassic.GetManufacturer()==lookup.Manufacturer && chassic.SerialNumber==lookup.SerialNumber { 
			// only check part number if is specified on both side
			if lookup.PartNumber!="" && chassic.GetPartNumber()!="" && lookup.PartNumber!=chassic.GetPartNumber() { 
				continue
			}
			return  &service.ChassisEntity{Name: chassic.GetName(),
				BootMode: chassic.GetBootMode().String(),},nil
		}
	}
	return nil, fmt.Errorf("could not resolve chassis with serial#: %s and manufacturer: %s",lookup.SerialNumber ,lookup.Manufacturer)
}



func (m *InMemoryEntityManager)	GetBootstrapData(bootRequest *bootz.GetBootstrapDataRequest, cc *bootz.ControlCard) (*bootz.BootstrapDataResponse, error){
	chDesc:= bootRequest.GetChassisDescriptor()
	lookup:= service.EntityLookup{SerialNumber: chDesc.SerialNumber,
		PartNumber: chDesc.PartNumber,
		Manufacturer: chDesc.Manufacturer,}
	_, err := m.ResolveChassis(lookup);  if err!=nil {
		return nil, err
	}


	

	return &bootz.BootstrapDataResponse{}, nil
}
func (*InMemoryEntityManager) SetStatus(service.EntityLookup, bootz.ReportStatusRequest) error {
	return nil
}
func (*InMemoryEntityManager) Sign(resp *bootz.GetBootstrapDataResponse) error {
	return nil
}

func New(chassisConfigFile string) (service.EntityManager, error){
	newManager:=&InMemoryEntityManager{}
	if chassisConfigFile==""{
		return newManager,nil
	}
	protoTextFile, err := os.ReadFile(chassisConfigFile)
    if err != nil {
        log.Errorf("Error in opening file %s : #%v ", chassisConfigFile, err)
		return nil, err
    }
	//newManager.devices=map[string]device{}
	entities :=epb.Entities{}
    err = prototext.Unmarshal(protoTextFile, &entities)
    if err != nil {
        log.Errorf("Error in un-marshalling %s: %v", protoTextFile, err)
		return nil, err
    }
	log.Printf("New entity manager is initialized successfully from chassis config file %s", chassisConfigFile)
	newManager.chassisConfigs= entities.GetChassis()
	return  newManager,nil
}






