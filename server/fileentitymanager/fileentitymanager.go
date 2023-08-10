package fileentitymanager

import (
	//"context"
	"fmt"
	"os"

	"github.com/labstack/gommon/log"
	yaml "gopkg.in/yaml.v3"

	"github.com/openconfig/bootz/proto/bootz"
	"github.com/openconfig/bootz/server/service"
	//"github.com/openconfig/gnmi/errlist"
	//"google.golang.org/grpc/codes"
	//"google.golang.org/grpc/status"
)

type manager struct {
	devices []device
} 

type device struct {
	Name             string `yaml:"Name"`
	Serial           string `yaml:"Serial"`
	PartNumber       string `yaml:"PartNumber"`
	Manufacturer     string `yaml:"Manufacturer"`
	OwnerShipVoucher string `yaml:"OwnerShipVoucher"`
	BootPasswordHash string `yaml:"BootPasswordHash"`
	Image            struct {
		URL           string `yaml:"URL"`
		Name          string `yaml:"Name"`
		Version       string `yaml:"Version"`
		ImageHash     string `yaml:"ImageHash""`
		HashAlgorithm string `yaml:"HashAlgorithm""`
	} `yaml:"Image"`
	Bootconfig struct {
		Metadata struct {
		} `yaml:"Metadata""`
		VendorConfig     string `yaml:"VendorConfig""`
		OcConfig         string `yaml:"OcConfig""`
		BootloaderConfig struct {
		} `yaml:"BootloaderConfig""`
	} `yaml:"Bootconfig"`
	GNSIConfig struct {
		ServerTrustCert string `yaml:"ServerTrustCert"`
		Credentials     string `yaml:"Credentials"`
		Pathz           string `yaml:"Pathz"`
		Authz           string `yaml:"Authz"`
		Certz           string `yaml:"Certz"`
	} `yaml:"gNSIConfig"`
}



func (m *manager) ResolveChassis(lookup service.EntityLookup) (*service.ChassisEntity, error) {
	for _,device := range m.devices {
		if device.Manufacturer==lookup.Manufacturer && device.Serial==lookup.SerialNumber {
			return  &service.ChassisEntity{SerialNumber: device.Serial,
				Manufacturer: device.Manufacturer,
				PartNumber: device.PartNumber,},nil
		}
	}
	return nil, fmt.Errorf("Could not resolve chassis %s with serial#: %s and manufacturer: %s", lookup.DeviceName,lookup.SerialNumber ,lookup.Manufacturer)

}
func (*manager)	GetBootstrapData(*bootz.ControlCard) (bootz.BootstrapDataResponse, error){
	return bootz.BootstrapDataResponse{}, nil
}
func (*manager) SetStatus(service.EntityLookup, bootz.ReportStatusRequest) error {
	return nil
}
func (*manager) Sign(resp *bootz.GetBootstrapDataResponse) error {
	return nil
}

func New(deviceConfig string) (service.EntityManager, error){
	yamlFile, err := os.ReadFile(deviceConfig)
    if err != nil {
        log.Errorf("Error in opening file %s : #%v ", deviceConfig, err)
		return nil, err
    }
	newManager:=&manager{}
	//newManager.devices=map[string]device{}
	devices :=[]device{}
    err = yaml.Unmarshal(yamlFile, &devices)
    if err != nil {
        log.Errorf("Error in un-marshalling %s: %v", devices, err)
		return nil, err
    }
	log.Printf("New entity manager is initialized successfully from config file %s", deviceConfig)
	return  newManager,nil
}






