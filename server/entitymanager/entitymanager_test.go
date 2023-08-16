package entitymanager

import (
	"github.com/h-fam/errdiff"
	"testing"

	"github.com/openconfig/bootz/proto/bootz"
	"github.com/openconfig/bootz/server/entitymanager/proto/entity"
)

func TestNew(t *testing.T) {
	t.Run("Test New with config file", func(t *testing.T) {
		_, err := New("testdata/chassis.prototxt")
		if err != nil {
			t.Fatalf("Could not instantiate entity manager from testdata/chassis.prototxt, err: %v", err)
		}
	})

	t.Run("Test New with config file", func(t *testing.T) {
		_, err := New("")
		if err != nil {
			t.Fatalf("Could not instantiate entity manager without config file, err: %v", err)
		}
	})
}

type test struct {
	name          string
	chassisConfig entity.Entities
	chassisDesc   bootz.ChassisDescriptor
	wantErr       string
}

func TestResolve(t *testing.T) {
	tests := []*test{
		{
			name: "Successful Resolve with Serial and Manufacture ",
			chassisConfig: entity.Entities{
				Chassis: []*entity.Chassis{
					{
						SerialNumber: "1234",
						Manufacturer: "cisco",
					},
				},
			},
			chassisDesc: bootz.ChassisDescriptor{
				Manufacturer: "cisco",
				SerialNumber: "1234",
			},
			wantErr: "",
		},
		{
			name: "UnSuccessful Resolve with Serial and Manufacture ",
			chassisConfig: entity.Entities{
				Chassis: []*entity.Chassis{
					{
						SerialNumber: "1232",
						Manufacturer: "cisco",
					},
				},
			},
			chassisDesc: bootz.ChassisDescriptor{
				Manufacturer: "cisco",
				SerialNumber: "1234",
			},
			wantErr: "could not resolve chassis with serial#: 1234 and manufacturer: cisco",
		},
		{
			name: "UnSuccessful Resolve with not matching product number",
			chassisConfig: entity.Entities{
				Chassis: []*entity.Chassis{
					{
						SerialNumber: "1234",
						Manufacturer: "cisco",
						PartNumber:   "1234",
					},
				},
			},
			chassisDesc: bootz.ChassisDescriptor{
				Manufacturer: "cisco",
				SerialNumber: "1234",
			},
			wantErr: "could not resolve chassis with serial#: 1234 and manufacturer: cisco",
		},
		{
			name: "Successful Resolve with matching product number",
			chassisConfig: entity.Entities{
				Chassis: []*entity.Chassis{
					{
						SerialNumber: "1234",
						Manufacturer: "cisco",
						PartNumber:   "1234",
					},
				},
			},
			chassisDesc: bootz.ChassisDescriptor{
				Manufacturer: "cisco",
				SerialNumber: "1234",
				PartNumber:   "1234",
			},
			wantErr: "",
		},
		{
			name: "UnSuccessful Resolve with not matching controller cards",
			chassisConfig: entity.Entities{
				Chassis: []*entity.Chassis{
					{
						SerialNumber: "1234",
						Manufacturer: "cisco",
						PartNumber:   "1234",
						ControllerCards: []*bootz.ControlCard{
							{
								SerialNumber: "1234",
								PartNumber:   "321",
							},
						},
					},
				},
			},
			chassisDesc: bootz.ChassisDescriptor{
				Manufacturer: "cisco",
				SerialNumber: "1234",
				PartNumber:   "1234",
			},
			wantErr: "could not resolve chassis with serial#: 1234 and manufacturer: cisco",
		},

		{
			name: "Successful Resolve with matching controller cards",
			chassisConfig: entity.Entities{
				Chassis: []*entity.Chassis{
					{
						SerialNumber: "1234",
						Manufacturer: "cisco",
						PartNumber:   "1234",
						ControllerCards: []*bootz.ControlCard{
							{
								SerialNumber: "1234",
								PartNumber:   "321",
							},
						},
					},
				},
			},
			chassisDesc: bootz.ChassisDescriptor{
				Manufacturer: "cisco",
				SerialNumber: "1234",
				PartNumber:   "1234",
				ControlCards: []*bootz.ControlCard{
					{
						PartNumber:   "321",
						SerialNumber: "1234",
					},
				},
			},
			wantErr: "",
		},
		{
			name: "Successful Resolve with matching two controller cards",
			chassisConfig: entity.Entities{
				Chassis: []*entity.Chassis{
					{
						SerialNumber: "1234",
						Manufacturer: "cisco",
						PartNumber:   "1234",
						ControllerCards: []*bootz.ControlCard{
							{
								SerialNumber: "1234",
								PartNumber:   "321",
							},
							{
								PartNumber:   "1111",
								SerialNumber: "2222",
							},
						},
					},
				},
			},
			chassisDesc: bootz.ChassisDescriptor{
				Manufacturer: "cisco",
				SerialNumber: "1234",
				PartNumber:   "1234",
				ControlCards: []*bootz.ControlCard{
					{
						PartNumber:   "321",
						SerialNumber: "1234",
					},
					{
						PartNumber:   "1111",
						SerialNumber: "2222",
					},
				},
			},
			wantErr: "",
		},
		{
			name: "UnSuccessful Resolve with matching two controller cards",
			chassisConfig: entity.Entities{
				Chassis: []*entity.Chassis{
					{
						SerialNumber: "1234",
						Manufacturer: "cisco",
						PartNumber:   "1234",
						ControllerCards: []*bootz.ControlCard{
							{
								SerialNumber: "1234",
								PartNumber:   "321",
							},
							{
								PartNumber:   "1111",
								SerialNumber: "2222",
							},
						},
					},
				},
			},
			chassisDesc: bootz.ChassisDescriptor{
				Manufacturer: "cisco",
				SerialNumber: "1234",
				PartNumber:   "1234",
				ControlCards: []*bootz.ControlCard{
					{
						PartNumber:   "321",
						SerialNumber: "1234",
					},
					{
						PartNumber:   "32233331",
						SerialNumber: "12444434",
					},
				},
			},
			wantErr: "could not resolve chassis with serial#: 1234 and manufacturer: cisco",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			em := entityManager{
				chassisConfigs: tt.chassisConfig.Chassis,
			}
			_, err := em.ResolveChassis(&tt.chassisDesc)
			if s := errdiff.Check(err, tt.wantErr); s != "" {
				t.Errorf("Expected error %s, but got error %v", tt.wantErr, err)
			}
		})
	}

}

func TestBootStrapResponse(t *testing.T) {
	tests := []*test{
		{name: "t1",
			chassisConfig: entity.Entities{},
			chassisDesc:   bootz.ChassisDescriptor{},
			wantErr:       "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			em := entityManager{
				chassisConfigs: tt.chassisConfig.Chassis,
			}
			_, err := em.ResolveChassis(&tt.chassisDesc)
			if s := errdiff.Check(err, tt.wantErr); s != "" {
				t.Errorf("Expected error %s, but got error %v", tt.wantErr, err)
			}
		})
	}
}
