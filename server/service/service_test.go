package service

import (
	"context"
	"fmt"
	"testing"

	"github.com/openconfig/bootz/proto/bootz"
)

type fakeEntityManager struct {
	simFailure bool
}

// FetchOwnershipVoucher retrieves the ownership voucher for a control card
func (f *fakeEntityManager) FetchOwnershipVoucher(string) (string, error) {
	if f.simFailure {
		return "", fmt.Errorf("fetchOwnershipVoucher is failed")
	}
	return "fakeOV", nil
}

// ResolveChassis returns an entity based on the provided lookup.
func (f *fakeEntityManager) ResolveChassis(lookup *EntityLookup) (*ChassisEntity, error) {
	if f.simFailure {
		return nil, fmt.Errorf("resolve chassis is failed")
	}
	return &ChassisEntity{}, nil
}

func (f *fakeEntityManager) GetBootstrapData(c *bootz.ControlCard) (*bootz.BootstrapDataResponse, error) {
	if f.simFailure {
		return nil, fmt.Errorf("get bootstrap data is failed")
	}
	return &bootz.BootstrapDataResponse{
		SerialNum: c.SerialNumber,
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
			VendorConfig: []byte("Vendor Config"),
			OcConfig:     []byte("OC Config"),
		},
		Credentials: &bootz.Credentials{},
		// TODO: Populate pathz, authz and certificates.
	}, nil
}

func (f *fakeEntityManager) SetStatus(req *bootz.ReportStatusRequest) error {
	if f.simFailure {
		return fmt.Errorf("setstatus is failed")
	}
	return nil
}

// Sign unmarshals the SignedResponse bytes then generates a signature from its Ownership Certificate private key.
func (f *fakeEntityManager) Sign(resp *bootz.GetBootstrapDataResponse, serial string) error {
	if f.simFailure {
		return fmt.Errorf("sign is failed")
	}
	return nil
}

// The following test shows how a test can use status API
// TODO: will complete with diffrence cases
func TestBootLog(t *testing.T) {
	bootReq := &bootz.GetBootstrapDataRequest{ChassisDescriptor: &bootz.ChassisDescriptor{
		Manufacturer: "Cisco",
		SerialNumber: "1234",
		PartNumber:   "1234",
		ControlCards: []*bootz.ControlCard{
			{
				SerialNumber: "1234A",
				PartNumber:   "1234A",
			},
			{
				SerialNumber: "1234B",
				PartNumber:   "1234B",
			},
		},
	},
	}
	bootzStatusReq := &bootz.ReportStatusRequest{
		States: []*bootz.ControlCardState{
			{
				SerialNumber: "1234A",
				Status:       bootz.ControlCardState_CONTROL_CARD_STATUS_INITIALIZED,
			},
			{
				SerialNumber: "12345",
				Status:       bootz.ControlCardState_CONTROL_CARD_STATUS_NOT_INITIALIZED,
			},
		},
	}
	lookup := EntityLookup{
		Manufacturer: "Cisco",
		SerialNumber: "1234",
	}
	fakeEm := &fakeEntityManager{}
	s := New(fakeEm)
	t.Run("Successfull boot test", func(t *testing.T) {
		_, err := s.GetBootstrapData(context.Background(), bootReq)
		if err != nil {
			t.Errorf("Got unexpected error %v", err)
		}
		if !s.IsChassisConnected(lookup) {
			t.Errorf("Connection log for chassis is not recorded")
		}
		bootLog, err := s.GetBootStatus("1234A")
		if err != nil {
			t.Errorf("The bootlog for controller card 1234A is missing")
		}
		if bootLog.Err != nil {
			t.Errorf("Boot error is expcted to be nil, but got %v", bootLog.Err)
		}
		s.ReportStatus(context.Background(), bootzStatusReq)
		// TODO: add check for log details
	})

	// add test for negetive scenario

}
