package entitymanager

import (
	//"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	//"crypto/sha512"

	"github.com/labstack/gommon/log"

	"github.com/openconfig/bootz/proto/bootz"
	epb "github.com/openconfig/bootz/server/entitymanager/proto/entity"
	authz "github.com/openconfig/gnsi/authz"
	certz "github.com/openconfig/gnsi/certz"
	pathz "github.com/openconfig/gnsi/pathz"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	//credz "github.com/openconfig/gnsi/credentialz"

	"github.com/openconfig/bootz/server/service"
	"google.golang.org/protobuf/encoding/prototext"
)

type InMemoryEntityManager struct {
	chassisConfigs []*epb.Chassis
}

type bootLog struct {
	BootMode       bootz.BootMode
	StartTimeStamp uint64
	EndTimeStamp   uint64
	Status         []bootz.ReportStatusRequest_BootstrapStatus
	BootResponse   *bootz.BootstrapDataResponse
	BootRequest    *bootz.GetBootstrapDataRequest
	Err            error
}

func (m *InMemoryEntityManager) ResolveChassis(chassDesc *bootz.ChassisDescriptor) (*service.ChassisEntity, error) {
	for _, chassConf := range m.chassisConfigs {
		// matching on Manufacturer and serial number is the must
		if chassConf.GetManufacturer() == chassDesc.GetManufacturer() && chassConf.SerialNumber == chassDesc.GetSerialNumber() {
			// only check part number if is specified on both side
			if chassConf.GetPartNumber() != "" && chassDesc.GetPartNumber() != chassConf.GetPartNumber() {
				continue
			}
			// check for controller match if they provided in config
			found:=0
			opts:= []cmp.Option{
				cmpopts.IgnoreUnexported(bootz.ControlCard{}),
			}
			if len(chassConf.GetControllerCards())>=1 {
				for _,ccInConfig := range chassConf.GetControllerCards(){
					for _,ccInBootReq := range chassDesc.GetControlCards(){
						if cmp.Equal(ccInConfig,ccInBootReq, opts...) {
							found+=1
							break
						}
					}
				}
			}
			if found != len(chassConf.GetControllerCards()) {
				continue
			}
			return &service.ChassisEntity{
				BootMode: chassConf.GetBootMode(),
				Name:     chassConf.GetName()}, nil
		}
	}
	return nil, fmt.Errorf("could not resolve chassis with serial#: %s and manufacturer: %s", chassDesc.GetSerialNumber(), chassDesc.GetManufacturer())
}

func (m *InMemoryEntityManager) GetChassisConfig(name string) *epb.Chassis {
	for _, chassic := range m.chassisConfigs {
		if chassic.Name == name {
			return chassic
		}
	}
	return &epb.Chassis{}
}

func loadAndValidateJSONfile(jsonFilePath string) ([]byte, error) {
	jsonByte, err := os.ReadFile(string(jsonFilePath))
	if err != nil {
		return nil, fmt.Errorf("could not populate oc config %v", err)
	}
	if !json.Valid(jsonByte) {
		return nil, fmt.Errorf("could not populate oc config, the oc config is not a valid json")
	}
	return jsonByte, err
}

func populateBootConfig(conf *epb.BootConfig) (*bootz.BootConfig, error) {
	bootConfig := &bootz.BootConfig{}
	if conf.GetOcConfigFile() != "" {
		ocConf, err := loadAndValidateJSONfile(conf.GetOcConfigFile())
		if err != nil {
			return nil, err
		}
		bootConfig.OcConfig = ocConf
	}
	if conf.GetVendorConfigFile() != "" {
		cliConf, err := os.ReadFile(string(conf.VendorConfigFile))
		if err != nil {
			return nil, fmt.Errorf("could not populate vendor config %v", err)
		}
		bootConfig.VendorConfig = cliConf
	}
	bootConfig.Metadata = conf.GetMetadata()
	bootConfig.BootloaderConfig = conf.GetBootloaderConfig()
	return bootConfig, nil
}

func populateAuthzConfig(conf *epb.GNSIConfig) (*authz.UploadRequest, error) {
	if conf.GetAuthzUploadFile() == "" {
		return nil, nil
	}
	authzPolicy, err := loadAndValidateJSONfile(conf.GetAuthzUploadFile())
	if err != nil {
		return nil, err
	}
	uploadReques := &authz.UploadRequest{
		Version:   "bootz",
		CreatedOn: uint64(time.Now().UnixMilli()),
		Policy:    string(authzPolicy),
	}
	return uploadReques, nil
}

func populatePathzConfig(conf *epb.GNSIConfig) (*pathz.UploadRequest, error) {
	if conf.GetPathzUploadFile() == "" {
		return nil, nil
	}
	pathzPolicyJson, err := loadAndValidateJSONfile(conf.GetPathzUploadFile())
	if err != nil {
		return nil, err
	}
	pathzPolicy := &pathz.AuthorizationPolicy{}
	err = json.Unmarshal(pathzPolicyJson, pathzPolicy)
	if err != nil {
		return nil, err
	}
	uploadReques := &pathz.UploadRequest{
		Version:   "bootz",
		CreatedOn: uint64(time.Now().UnixMilli()),
		Policy:    pathzPolicy,
	}
	return uploadReques, nil
}

func populateCertzConfig(conf *epb.GNSIConfig) (*certz.UploadRequest, error) {
	if conf.GetCertzUploadFile() == "" {
		return nil, nil
	}
	return nil, nil
	// TODO
}

func populateCredzConfig(conf *epb.GNSIConfig) (*bootz.Credentials, error) {
	if conf.GetCredentialsFile() == "" {
		return nil, nil
	}
	return nil, nil
	// TODO
}

func (m *InMemoryEntityManager) GetBootstrapData(bootRequest *bootz.GetBootstrapDataRequest, cc *bootz.ControlCard) (*bootz.BootstrapDataResponse, error) {
	chDesc := bootRequest.GetChassisDescriptor()
	chassicEn, err := m.ResolveChassis(chDesc)
	if err != nil {
		return nil, err
	}
	chassisConf := m.GetChassisConfig(chassicEn.Name)

	bootStrapData := &bootz.BootstrapDataResponse{}

	bootConfig, err := populateBootConfig(chassisConf.Config.GetBootConfig())
	if err != nil {
		return nil, fmt.Errorf("error in populating bootConfig %v", err)
	}
	bootStrapData.BootConfig = bootConfig

	authzUploadReq, err := populateAuthzConfig(chassisConf.Config.GetGnsiConfig())
	if err != nil {
		return nil, fmt.Errorf("error in populating authz config: %v", err)

	}
	bootStrapData.Authz = authzUploadReq

	pathzUploadReq, err := populatePathzConfig(chassisConf.Config.GetGnsiConfig())
	if err != nil {
		return nil, fmt.Errorf("error in populating authz config: %v", err)

	}
	bootStrapData.Pathz = pathzUploadReq

	bootStrapData.BootPasswordHash = chassisConf.GetBootloaderPasswordHash()
	bootStrapData.SerialNum = cc.SerialNumber

	bootStrapData.IntendedImage= chassisConf.SoftwareImage


	// TODO
	//bootStrapData.ServerTrustCert:= readServerCert()

	return bootStrapData, nil
}


func (*InMemoryEntityManager) Sign(resp *bootz.GetBootstrapDataResponse) error {
	return nil
}

func New(chassisConfigFile string) (service.EntityManager, error) {
	newManager := &InMemoryEntityManager{}
	if chassisConfigFile == "" {
		return newManager, nil
	}
	protoTextFile, err := os.ReadFile(chassisConfigFile)
	if err != nil {
		log.Errorf("Error in opening file %s : #%v ", chassisConfigFile, err)
		return nil, err
	}
	//newManager.devices=map[string]device{}
	entities := epb.Entities{}
	err = prototext.Unmarshal(protoTextFile, &entities)
	if err != nil {
		log.Errorf("Error in un-marshalling %s: %v", protoTextFile, err)
		return nil, err
	}
	log.Printf("New entity manager is initialized successfully from chassis config file %s", chassisConfigFile)
	newManager.chassisConfigs = entities.GetChassis()
	return newManager, nil
}
