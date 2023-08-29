package entitymanager

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/h-fam/errdiff"
	"github.com/openconfig/bootz/proto/bootz"
	"github.com/openconfig/bootz/server/entitymanager/proto/entity"
	"github.com/openconfig/bootz/server/service"
	"google.golang.org/protobuf/proto"
)

var (
	ov1     = "MIIRowYJKoZIhvcNAQcCoIIRlDCCEZACAQExDTALBglghkgBZQMEAgEwggjWBgkqhkiG9w0BBwGgggjHBIIIw3siaWV0Zi12b3VjaGVyOnZvdWNoZXIiOnsiY3JlYXRlZC1vbiI6IjIwMjMtMDgtMDkgMjM6NDk6MDYuMjc3MzQ3NCArMDAwMCBVVEMgbT0rMC45MzM0ODc2MDEiLCJleHBpcmVzLW9uIjoiMjAyNC0wOC0wOCAyMzo0OTowNi4yNzczNDc0ICswMDAwIFVUQyBtPSszMTUzNjAwMC45MzM0ODc2MDEiLCJzZXJpYWwtbnVtYmVyIjoiMTIzQSIsImFzc2VydGlvbiI6IiIsInBpbm5lZC1kb21haW4tY2VydCI6Ik1JSUZtVENDQTRHZ0F3SUJBZ0lDQitjd0RRWUpLb1pJaHZjTkFRRUxCUUF3WGpFTE1Ba0dBMVVFQmhNQ1ZWTXhcbkN6QUpCZ05WQkFnVEFrTkJNUll3RkFZRFZRUUhFdzFOYjNWdWRHRnBiaUJXYVdWM01ROHdEUVlEVlFRS0V3WkhcbmIyOW5iR1V4R1RBWEJnTlZCQU1URUVSbGRtbGpaU0JQZDI1bGNpQlFSRU13SGhjTk1qTXdPREE1TWpNME9UQTFcbldoY05Nek13T0RBNU1qTTBPVEExV2pCZU1Rc3dDUVlEVlFRR0V3SlZVekVMTUFrR0ExVUVDQk1DUTBFeEZqQVVcbkJnTlZCQWNURFUxdmRXNTBZV2x1SUZacFpYY3hEekFOQmdOVkJBb1RCa2R2YjJkc1pURVpNQmNHQTFVRUF4TVFcblJHVjJhV05sSUU5M2JtVnlJRkJFUXpDQ0FpSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnSVBBRENDQWdvQ2dnSUJcbkFKMlVoNHNYSFE2M0R4NjRobjJrendDSURYSXgraVJSMEF4RHg5b0tnTk1aNTVVd2x3bmY1QjlGb1ZsVmRVbS9cblRFUlpGOVo2cS9PRGdhM0ZKWlZXdE1XZFBKVlZ0ZFJaU2VpUDkycDRpSHk5czNMNEVJUzhpK3NJMXlRNVFGTjZcbmZpTllyM1gwalUvMWFDOG44a3VNR2U4TzN6Wk8zV2FwNVFkVkFaNXpTZlBMa25TR3BrSlN0WUdEM2V4ZFc4OXdcbm5YMkgvOXFPRlFwRnFyZklyMnN4bGYyZ3p6ZGI2VExFcGpKV2R5VWFDUU9SZEFJUWJmYkRXcm5GUGNWR014UDNcbkx4YU9rSHF6d2FMdmhpR21raTNJTnd3Ui9uK2dWMDZnTHpncjh5RGl0Tk00NHArc3ptR2ZrbzR2ZUZUMWZkQ21cbjBFSjNwbkpQb2hMdWZkSjFsQnZ5bWNndDRxZHRGZTZ1UFRMckFqMmtPOEt5L000UFZQWExUMXBHRUxHOXlHRUFcblBtWHVWRERCbGh1c29WdEE4alBCdXBzS09FQ0NOZ0RhS0FZQndibHJ1MUIvLzBEQTU4VEx2ZVpYQ0VLbFJwa2pcbklSSUd0cmg0YVhiK2liZVV3YVVFSWIwUXo1RWVDRjFPS0Z2cDVTL3hTMkJtQ0VpOGxYTktZTjIzMXppM2xKOS9cbnNLeWdJL1p4VnBySnBpRmxsazlEOFVMRGxrcmx5dkxmYVdmS2VvVmhZQm41d1dJZmVTWnhQK0VhRUlBeERkNjZcblN3aGxOQjlYMFM1OTJkTW9jU1VoQ204cXptQXRBZDM3dWxGUXh6SjM1TUlPNFZxSXZub3Nhb1dwSE9mQXRwT0hcbmhsdGE4blVmQTN0Y1ZJNDFGc3JKVEdTcEtqQ05RZThhSGxSZkxMdGRQNVNaQWdNQkFBR2pZVEJmTUE0R0ExVWRcbkR3RUIvd1FFQXdJQ2hEQWRCZ05WSFNVRUZqQVVCZ2dyQmdFRkJRY0RBZ1lJS3dZQkJRVUhBd0V3RHdZRFZSMFRcbkFRSC9CQVV3QXdFQi96QWRCZ05WSFE0RUZnUVU0TGk2aEJneFFrQU1Hb1pWZXBqS2VkclY5aHN3RFFZSktvWklcbmh2Y05BUUVMQlFBRGdnSUJBQ1pLem4waStpeVFZK0svM29kVUFrcEZCcFlHK2xWbjlVZXlaU3YwY2cwejdOdnVcbjhTdEFLTWRJaDFPWWxQNGNEVkNPSWxURmFoN1dUK05CTTdRODM1bS9MZndzOS9MeXpjWGhsNC9EbXVFUFVId1hcbkVOZVoxRmZIRXNlUzRwRVpxQ2hPNGt0NDhNbTc2ZzZJMXR1cGNSR0F2RUt2cUdxVnY0SDRPZk9xM3dyeHFOd0lcbnlyYkRXN1NXS3JONFY0V3E4SUc2bGxzQnRFQ21ySjdmN3l2UGhqZ3pkdUFOeDBkS2tJQkRzRkNPeExEWnFUclJcbkFHN3hVNzQxdTBzelhUd2JQbmw0b0hmQVVRQ3hSa2RaUXVlUVZKeHIzeDB1eUVYL2x4UHZTUFFHRXE2WFo3RnFcbnNnM1hCUlJWZUN0Z292NTNNdmpGSVBTbmtkb1NzZVVOODhQQi94WEhqT2NxaEFYWTNzT3R4WXNadHM2bGFtNHpcbnJtaTRiVSttM0xFVEJWam5iT0lnZ0ZhRDk5RjlYYXFyd2R5ZTVaOEd0OU41bnpBcm5wTEtKUDFNdVR4dWZ5VjVcbllmNU5SZmR1UnhrdGhxRnFwdGgwRUFBYlltdVlPelBTUnUrODRheE5nOTcyN2ZhcWoyaTZZZitQdHVVS0haMzJcbkkzRmEvUldXQ3YxRzJzMit0K3ZvRnJhZVFQOWZBTHJMZ0pvakRaaTNzeml6OGJ3ZVFOMzZyYk9MVGxHN0EybFVcblNqOXJqd2R2RHh6cWIzQjhHR2crYXBFMjRIUTdvZWRDd3Z1UFJiK1o5aWRkaXg1S09kUmNqKy9kNng2dWJ1OWxcbkNnaTE1dTF2QXROaUV5dTdOeitGOENCRkRoWnMrMzJVM2lvS2Q0U0RQSEpsQ1plUVc5OUx0dVEzOTRUaCIsImRvbWFpbi1jZXJ0LXJldm9jYXRpb24tY2hlY2tzIjpmYWxzZX19oIIFozCCBZ8wggOHoAMCAQICAgfnMA0GCSqGSIb3DQEBCwUAMGExCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNTW91bnRhaW4gVmlldzEOMAwGA1UEChMFQ2lzY28xHTAbBgNVBAMTFE1hbnVmYWN0dXJlciBSb290IENBMB4XDTIzMDgwOTIzNDkwNVoXDTMzMDgwOTIzNDkwNVowYTELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MQ4wDAYDVQQKEwVDaXNjbzEdMBsGA1UEAxMUTWFudWZhY3R1cmVyIFJvb3QgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCT8XUaoChCJr7MxG5ay5dFJhfzo1OOMMUXij+cUaxaWBBXAsi6B24ka0sRvGeoPZoZiwy9/W5SaNTWC0CRTryDAwbuEnPgvM3aHCn0EydY6nS1O1cHVUHQ/wYEsfiD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"
	ov2     = "MIIRowYJKoZIhvcNAQcCoIIRlDCCEZACAQExDTALBglghkgBZQMEAgEwggjWBgkqhkiG9w0BBwGgggjHBIIIw3siaWV0Zi12b3VjaGVyOnZvdWNoZXIiOnsiY3JlYXRlZC1vbiI6IjIwMjMtMDgtMDkgMjM6NDk6MDYuMjg5NzEyMyArMDAwMCBVVEMgbT0rMC45NDU4NTI2MDEiLCJleHBpcmVzLW9uIjoiMjAyNC0wOC0wOCAyMzo0OTowNi4yODk3MTIzICswMDAwIFVUQyBtPSszMTUzNjAwMC45NDU4NTI2MDEiLCJzZXJpYWwtbnVtYmVyIjoiMTIzQiIsImFzc2VydGlvbiI6IiIsInBpbm5lZC1kb21haW4tY2VydCI6Ik1JSUZtVENDQTRHZ0F3SUJBZ0lDQitjd0RRWUpLb1pJaHZjTkFRRUxCUUF3WGpFTE1Ba0dBMVVFQmhNQ1ZWTXhcbkN6QUpCZ05WQkFnVEFrTkJNUll3RkFZRFZRUUhFdzFOYjNWdWRHRnBiaUJXYVdWM01ROHdEUVlEVlFRS0V3WkhcbmIyOW5iR1V4R1RBWEJnTlZCQU1URUVSbGRtbGpaU0JQZDI1bGNpQlFSRU13SGhjTk1qTXdPREE1TWpNME9UQTFcbldoY05Nek13T0RBNU1qTTBPVEExV2pCZU1Rc3dDUVlEVlFRR0V3SlZVekVMTUFrR0ExVUVDQk1DUTBFeEZqQVVcbkJnTlZCQWNURFUxdmRXNTBZV2x1SUZacFpYY3hEekFOQmdOVkJBb1RCa2R2YjJkc1pURVpNQmNHQTFVRUF4TVFcblJHVjJhV05sSUU5M2JtVnlJRkJFUXpDQ0FpSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnSVBBRENDQWdvQ2dnSUJcbkFKMlVoNHNYSFE2M0R4NjRobjJrendDSURYSXgraVJSMEF4RHg5b0tnTk1aNTVVd2x3bmY1QjlGb1ZsVmRVbS9cblRFUlpGOVo2cS9PRGdhM0ZKWlZXdE1XZFBKVlZ0ZFJaU2VpUDkycDRpSHk5czNMNEVJUzhpK3NJMXlRNVFGTjZcbmZpTllyM1gwalUvMWFDOG44a3VNR2U4TzN6Wk8zV2FwNVFkVkFaNXpTZlBMa25TR3BrSlN0WUdEM2V4ZFc4OXdcbm5YMkgvOXFPRlFwRnFyZklyMnN4bGYyZ3p6ZGI2VExFcGpKV2R5VWFDUU9SZEFJUWJmYkRXcm5GUGNWR014UDNcbkx4YU9rSHF6d2FMdmhpR21raTNJTnd3Ui9uK2dWMDZnTHpncjh5RGl0Tk00NHArc3ptR2ZrbzR2ZUZUMWZkQ21cbjBFSjNwbkpQb2hMdWZkSjFsQnZ5bWNndDRxZHRGZTZ1UFRMckFqMmtPOEt5L000UFZQWExUMXBHRUxHOXlHRUFcblBtWHVWRERCbGh1c29WdEE4alBCdXBzS09FQ0NOZ0RhS0FZQndibHJ1MUIvLzBEQTU4VEx2ZVpYQ0VLbFJwa2pcbklSSUd0cmg0YVhiK2liZVV3YVVFSWIwUXo1RWVDRjFPS0Z2cDVTL3hTMkJtQ0VpOGxYTktZTjIzMXppM2xKOS9cbnNLeWdJL1p4VnBySnBpRmxsazlEOFVMRGxrcmx5dkxmYVdmS2VvVmhZQm41d1dJZmVTWnhQK0VhRUlBeERkNjZcblN3aGxOQjlYMFM1OTJkTW9jU1VoQ204cXptQXRBZDM3dWxGUXh6SjM1TUlPNFZxSXZub3Nhb1dwSE9mQXRwT0hcbmhsdGE4blVmQTN0Y1ZJNDFGc3JKVEdTcEtqQ05RZThhSGxSZkxMdGRQNVNaQWdNQkFBR2pZVEJmTUE0R0ExVWRcbkR3RUIvd1FFQXdJQ2hEQWRCZ05WSFNVRUZqQVVCZ2dyQmdFRkJRY0RBZ1lJS3dZQkJRVUhBd0V3RHdZRFZSMFRcbkFRSC9CQVV3QXdFQi96QWRCZ05WSFE0RUZnUVU0TGk2aEJneFFrQU1Hb1pWZXBqS2VkclY5aHN3RFFZSktvWklcbmh2Y05BUUVMQlFBRGdnSUJBQ1pLem4waStpeVFZK0svM29kVUFrcEZCcFlHK2xWbjlVZXlaU3YwY2cwejdOdnVcbjhTdEFLTWRJaDFPWWxQNGNEVkNPSWxURmFoN1dUK05CTTdRODM1bS9MZndzOS9MeXpjWGhsNC9EbXVFUFVId1hcbkVOZVoxRmZIRXNlUzRwRVpxQ2hPNGt0NDhNbTc2ZzZJMXR1cGNSR0F2RUt2cUdxVnY0SDRPZk9xM3dyeHFOd0lcbnlyYkRXN1NXS3JONFY0V3E4SUc2bGxzQnRFQ21ySjdmN3l2UGhqZ3pkdUFOeDBkS2tJQkRzRkNPeExEWnFUclJcbkFHN3hVNzQxdTBzelhUd2JQbmw0b0hmQVVRQ3hSa2RaUXVlUVZKeHIzeDB1eUVYL2x4UHZTUFFHRXE2WFo3RnFcbnNnM1hCUlJWZUN0Z292NTNNdmpGSVBTbmtkb1NzZVVOODhQQi94WEhqT2NxaEFYWTNzT3R4WXNadHM2bGFtNHpcbnJtaTRiVSttM0xFVEJWam5iT0lnZ0ZhRDk5RjlYYXFyd2R5ZTVaOEd0OU41bnpBcm5wTEtKUDFNdVR4dWZ5VjVcbllmNU5SZmR1UnhrdGhxRnFwdGgwRUFBYlltdVlPelBTUnUrODRheE5nOTcyN2ZhcWoyaTZZZitQdHVVS0haMzJcbkkzRmEvUldXQ3YxRzJzMit0K3ZvRnJhZVFQOWZBTHJMZ0pvakRaaTNzeml6OGJ3ZVFOMzZyYk9MVGxHN0EybFVcblNqOXJqd2R2RHh6cWIzQjhHR2crYXBFMjRIUTdvZWRDd3Z1UFJiK1o5aWRkaXg1S09kUmNqKy9kNng2dWJ1OWxcbkNnaTE1dTF2QXROaUV5dTdOeitGOENCRkRoWnMrMzJVM2lvS2Q0U0RQSEpsQ1plUVc5OUx0dVEzOTRUaCIsImRvbWFpbi1jZXJ0LXJldm9jYXRpb24tY2hlY2tzIjpmYWxzZX19oIIFozCCBZ8wggOHoAMCAQICAgfnMA0GCSqGSIb3DQEBCwUAMGExCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNTW91bnRhaW4gVmlldzEOMAwGA1UEChMFQ2lzY28xHTAbBgNVBAMTFE1hbnVmYWN0dXJlciBSb290IENBMB4XDTIzMDgwOTIzNDkwNVoXDTMzMDgwOTIzNDkwNVowYTELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MQ4wDAYDVQQKEwVDaXNjbzEdMBsGA1UEAxMUTWFudWZhY3R1cmVyIFJvb3QgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCT8XUaoChCJr7MxG5ay5dFJhfzo1OOMMUXij+cUaxaWBBXAsi6B24ka0sRvGeoPZoZiwy9/W5SaNTWC0CRTryDAwbuEnPgvM3aHCn0EydY6nS1O1cHVUHQ/wYEsfiD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"
	chassis = entity.Chassis{
		Name:                   "test",
		SerialNumber:           "123",
		Manufacturer:           "Cisco",
		BootloaderPasswordHash: "ABCD123",
		BootMode:               bootz.BootMode_BOOT_MODE_INSECURE,
		Config: &entity.Config{
			BootConfig: &entity.BootConfig{},
			DhcpConfig: &entity.DHCPConfig{},
			GnsiConfig: &entity.GNSIConfig{},
		},
		SoftwareImage: &bootz.SoftwareImage{
			Name:          "Default Image",
			Version:       "1.0",
			Url:           "https://path/to/image",
			OsImageHash:   "ABCDEF",
			HashAlgorithm: "SHA256",
		},
		ControllerCards: []*entity.ControlCard{
			{
				SerialNumber:     "123A",
				PartNumber:       "123A",
				OwnershipVoucher: ov1,
			},
			{
				SerialNumber:     "123B",
				PartNumber:       "123B",
				OwnershipVoucher: ov2,
			},
		},
	}
)

func TestNew(t *testing.T) {
	tests := []struct {
		desc        string
		chassisConf string
		inventory   map[service.EntityLookup]*entity.Chassis
		defaults    *entity.Options
		wantErr     string
	}{
		{
			desc:        "Successful new with file",
			chassisConf: "../../testdata/inventory.prototxt",
			inventory: map[service.EntityLookup]*entity.Chassis{{SerialNumber: chassis.SerialNumber,
				Manufacturer: chassis.Manufacturer}: &chassis},
			defaults: &entity.Options{
				Bootzserver: "bootzip:....",
				ArtifactDir: "../../testdata/",
			},
		},
		{
			desc:        "Unsuccessful with wrong security artifacts",
			chassisConf: "../../testdata/inv_with_wrong_sec.prototxt",
			wantErr:     "security artifacts",
		},
		{
			desc:        "Unsuccessful new with wrong file",
			chassisConf: "../../testdata/wrong_inventory.prototxt",
			inventory:   map[service.EntityLookup]*entity.Chassis{},
			wantErr:     "proto:",
		},
		{
			desc:        "Unsuccessful new with wrong file path",
			chassisConf: "not/valid/path",
			inventory:   map[service.EntityLookup]*entity.Chassis{},
			wantErr:     "no such file or directory",
		},
		{
			desc:        "Successful new with empty file path",
			chassisConf: "",
			inventory:   map[service.EntityLookup]*entity.Chassis{},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			inv, err := New(test.chassisConf)
			if err == nil {
				opts := []cmp.Option{
					cmpopts.IgnoreUnexported(entity.Chassis{}, entity.Options{}, bootz.SoftwareImage{}, entity.DHCPConfig{}, entity.GNSIConfig{}, entity.BootConfig{}, entity.Config{}, entity.BootConfig{}, entity.ControlCard{}, service.EntityLookup{}),
				}
				if !cmp.Equal(inv.chassisInventory, test.inventory, opts...) {
					t.Errorf("Inventory list is not as expected, Diff: %s", cmp.Diff(inv.chassisInventory, test.inventory, opts...))
				}
				if !cmp.Equal(inv.defaults, test.defaults, opts...) {
					t.Errorf("Inventory list is not as expected, Diff: %s", cmp.Diff(inv.defaults, test.defaults, opts...))
				}
			}
			if s := errdiff.Substring(err, test.wantErr); s != "" {
				t.Errorf("Expected error %s, but got error %v", test.wantErr, err)
			}
		})
	}

}

func TestFetchOwnershipVoucher(t *testing.T) {
	tests := []struct {
		desc    string
		serial  string
		want    string
		wantErr bool
	}{{
		desc:    "Missing OV",
		serial:  "MissingSerial",
		wantErr: true,
	}, {
		desc:    "Found OV",
		serial:  "123A",
		want:    ov1,
		wantErr: false,
	}}

	em, _ := New("")

	em.chassisInventory[service.EntityLookup{Manufacturer: "Cisco", SerialNumber: "123"}] = &chassis

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			got, err := em.fetchOwnershipVoucher(&service.EntityLookup{Manufacturer: "Cisco", SerialNumber: "123"}, test.serial)
			if (err != nil) != test.wantErr {
				t.Fatalf("FetchOwnershipVoucher(%v) err = %v, want %v", test.serial, err, test.wantErr)
			}
			if !cmp.Equal(got, test.want) {
				t.Errorf("FetchOwnershipVoucher(%v) got %v, want %v", test.serial, got, test.want)
			}
		})
	}
}

func TestResolveChassis(t *testing.T) {
	tests := []struct {
		desc    string
		input   *service.EntityLookup
		want    *service.ChassisEntity
		wantErr bool
	}{{
		desc: "Default device",
		input: &service.EntityLookup{
			SerialNumber: "123",
			Manufacturer: "Cisco",
		},
		want: &service.ChassisEntity{
			BootMode: bootz.BootMode_BOOT_MODE_SECURE,
		},
	}, {
		desc: "Chassis Not Found",
		input: &service.EntityLookup{
			SerialNumber: "456",
			Manufacturer: "Cisco",
		},
		want:    nil,
		wantErr: true,
	},
	}
	em, _ := New("")
	em.AddChassis(bootz.BootMode_BOOT_MODE_SECURE, "Cisco", "123")

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			got, err := em.ResolveChassis(test.input)
			if (err != nil) != test.wantErr {
				t.Fatalf("ResolveChassis(%v) err = %v, want %v", test.input, err, test.wantErr)
			}
			if !cmp.Equal(got, test.want) {
				t.Errorf("ResolveChassis(%v) got %v, want %v", test.input, got, test.want)
			}
		})
	}
}

func TestSign(t *testing.T) {
	tests := []struct {
		desc    string
		chassis service.EntityLookup
		serial  string
		resp    *bootz.GetBootstrapDataResponse
		wantOV  string
		wantOC  bool
		wantErr bool
	}{{
		desc: "Success",
		chassis: service.EntityLookup{
			Manufacturer: "Cisco",
			SerialNumber: "123",
		},
		serial: "123A",
		resp: &bootz.GetBootstrapDataResponse{
			SignedResponse: &bootz.BootstrapDataSigned{
				Responses: []*bootz.BootstrapDataResponse{
					{SerialNum: "123A"},
				},
			},
		},
		wantOV:  ov1,
		wantOC:  true,
		wantErr: false,
	}, {
		desc:    "Empty response",
		resp:    &bootz.GetBootstrapDataResponse{},
		wantErr: true,
	},
	}

	em, _ := New("../../testdata/inventory.prototxt")
	artifacts, err := parseSecurityArtifacts(em.defaults.GetArtifactDir())
	if err != nil {
		t.Fatalf("Could not load security artifacts: %v", err)
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {

			err = em.Sign(test.resp, &test.chassis, test.serial)
			if err != nil {
				if test.wantErr {
					t.Skip()
				}
				t.Errorf("Sign() err = %v, want %v", err, test.wantErr)
			}
			signedResponseBytes, err := proto.Marshal(test.resp.GetSignedResponse())
			if err != nil {
				t.Fatal(err)
			}
			hashed := sha256.Sum256(signedResponseBytes)
			sigDecoded, err := base64.StdEncoding.DecodeString(test.resp.GetResponseSignature())
			if err != nil {
				t.Fatal(err)
			}

			block, _ := pem.Decode([]byte(artifacts.OC.Key))
			if block == nil {
				t.Fatal("unable to decode OC private key")
			}
			priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				t.Fatal("unable to parse OC private key")
			}

			err = rsa.VerifyPKCS1v15(&priv.PublicKey, crypto.SHA256, hashed[:], sigDecoded)
			if err != nil {
				t.Errorf("Sign() err == %v, want %v", err, test.wantErr)
			}
			if gotOV, wantOV := string(test.resp.GetOwnershipVoucher()), test.wantOV; gotOV != wantOV {
				t.Errorf("Sign() ov = %v, want %v", gotOV, wantOV)
			}
			if test.wantOC {
				if gotOC, wantOC := string(test.resp.GetOwnershipCertificate()), artifacts.OC.Cert; gotOC != wantOC {
					t.Errorf("Sign() oc = %v, want %v", gotOC, wantOC)
				}
			}
		})
	}
}

func TestSetStatus(t *testing.T) {
	tests := []struct {
		desc    string
		input   *bootz.ReportStatusRequest
		wantErr bool
	}{{
		desc: "No control card states",
		input: &bootz.ReportStatusRequest{
			Status:        bootz.ReportStatusRequest_BOOTSTRAP_STATUS_SUCCESS,
			StatusMessage: "Bootstrap status succeeded",
		},
		wantErr: true,
	}, {
		desc: "Control card initialized",
		input: &bootz.ReportStatusRequest{
			Status:        bootz.ReportStatusRequest_BOOTSTRAP_STATUS_SUCCESS,
			StatusMessage: "Bootstrap status succeeded",
			States: []*bootz.ControlCardState{
				{
					SerialNumber: "123A",
					Status:       *bootz.ControlCardState_CONTROL_CARD_STATUS_INITIALIZED.Enum(),
				},
			},
		},
		wantErr: false,
	}, {
		desc: "Unknown control card",
		input: &bootz.ReportStatusRequest{
			Status:        bootz.ReportStatusRequest_BOOTSTRAP_STATUS_SUCCESS,
			StatusMessage: "Bootstrap status succeeded",
			States: []*bootz.ControlCardState{
				{
					SerialNumber: "123C",
					Status:       *bootz.ControlCardState_CONTROL_CARD_STATUS_INITIALIZED.Enum(),
				},
			},
		},
		wantErr: true,
	},
	}
	em, _ := New("")
	em.AddChassis(bootz.BootMode_BOOT_MODE_SECURE, "Cisco", "123").AddControlCard("123A")

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			err := em.SetStatus(test.input)
			if (err != nil) != test.wantErr {
				t.Errorf("SetStatus(%v) err = %v, want %v", test.input, err, test.wantErr)
			}
		})
	}
}

func TestGetBootstrapData(t *testing.T) {
	tests := []struct {
		desc    string
		input   *bootz.ControlCard
		want    *bootz.BootstrapDataResponse
		wantErr bool
	}{{
		desc:    "No serial number",
		input:   &bootz.ControlCard{},
		wantErr: true,
	}, {
		desc: "Control card not found",
		input: &bootz.ControlCard{
			SerialNumber: "456A",
		},
		wantErr: true,
	}, {
		desc: "Successful bootstrap",
		input: &bootz.ControlCard{
			SerialNumber: "123A",
			PartNumber:   "123A",
		},
		want: &bootz.BootstrapDataResponse{
			SerialNum: "123A",
			IntendedImage: &bootz.SoftwareImage{
				Name:          "Default Image",
				Version:       "1.0",
				Url:           "https://path/to/image",
				OsImageHash:   "ABCDEF",
				HashAlgorithm: "SHA256",
			},
			BootPasswordHash: "ABCD123",
			ServerTrustCert:  "FakeTLSCert",
			BootConfig: &bootz.BootConfig{
				VendorConfig: []byte(""),
				OcConfig:     []byte(""),
			},
			Credentials: &bootz.Credentials{},
		},
		wantErr: false,
	},
	}

	em, _ := New("")
	em.chassisInventory[service.EntityLookup{Manufacturer: "Cisco", SerialNumber: "123"}] = &chassis

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			got, err := em.GetBootstrapData(&service.EntityLookup{Manufacturer: "Cisco", SerialNumber: "123"}, test.input)
			if (err != nil) != test.wantErr {
				t.Errorf("GetBootstrapData(%v) err = %v, want %v", test.input, err, test.wantErr)
			}
			if !proto.Equal(got, test.want) {
				t.Errorf("GetBootstrapData(%v) \n got: %v, \n want: %v", test.input, got, test.want)
			}
		})
	}
}

func TestLoadConfig(t *testing.T) {
	vendorCliConfig := `!! IOS XR Configuration 7.4.1
!! Last configuration change at Wed Aug 18 19:55:09 2021 by cisco
!
username cisco
 group root-lr
 group cisco-support
 password 7 01100F175804575D72
!
interface Loopback0
 ipv4 address 44.44.44.44 255.255.255.255
 ipv6 address 44::44/128
!
grpc
 dscp cs4
 port 57400
 max-streams 128
 max-streams-per-user 128
 address-family dual
 max-request-total 256
 max-request-per-user 32
!
hw-module profile pbr vrf-redirect
ssh server vrf default
end`
	tests := []struct {
		desc             string
		bootConfig       *entity.BootConfig
		wantBootConfig   *bootz.BootConfig
		wantVendorConfig []byte
		wantErr          string
	}{
		{
			desc: "Suceffull OC/vendor config",
			bootConfig: &entity.BootConfig{
				VendorConfigFile: "../../testdata/cisco.cfg",
				OcConfigFile:     "../../testdata/oc_config.prototext",
			},
			wantBootConfig: &bootz.BootConfig{
				VendorConfig: []byte(vendorCliConfig),
			},
			wantVendorConfig: []byte{},
			wantErr:          "",
		},
		{
			desc: "UnSuceffull OC config",
			bootConfig: &entity.BootConfig{
				VendorConfigFile: "../../testdata/cisco.cfg",
				OcConfigFile:     "../../testdata/wrong_oc_config.prototext",
			},
			wantBootConfig: &bootz.BootConfig{
				VendorConfig: []byte(vendorCliConfig),
			},
			wantVendorConfig: []byte{},
			wantErr:          "proto",
		},
		{
			desc: "UnSuceffull OC config due to path",
			bootConfig: &entity.BootConfig{
				VendorConfigFile: "../../testdata/cisco.cfg",
				OcConfigFile:     "../../wrong_path.prototext",
			},
			wantBootConfig: &bootz.BootConfig{
				VendorConfig: []byte(vendorCliConfig),
			},
			wantVendorConfig: []byte{},
			wantErr:          "file",
		},
		{
			desc: "UnSuceffull vendor config due to path",
			bootConfig: &entity.BootConfig{
				VendorConfigFile: "../../wrong/path",
				OcConfigFile:     "../../testdata/oc_config.prototext",
			},
			wantBootConfig: &bootz.BootConfig{
				VendorConfig: []byte(vendorCliConfig),
			},
			wantVendorConfig: []byte{},
			wantErr:          "file",
		},
	}
	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			gotBootConfig, err := populateBootConfig(test.bootConfig)
			if err == nil {
				if diff := cmp.Diff(test.wantBootConfig.GetVendorConfig(), gotBootConfig.GetVendorConfig()); diff != "" {
					t.Fatalf("wanted vendor config differs from the got config %s", diff)
				}
			}
			if errdiff.Substring(err, test.wantErr) != "" {
				t.Errorf("Unexocted error, %s", errdiff.Text(err, test.wantErr))
			}

		})
	}
}
