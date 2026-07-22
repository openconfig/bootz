// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package chassismanager is a chassis manager that manages chassis.
// The implementation here is an in-memory implementation primarily used for testing and qualification.
// For production usecase, you should replace this implementation with your own one.
package chassismanager

import (
	"context"
	"fmt"

	log "github.com/golang/glog"
	"github.com/openconfig/bootz/common/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	bpb "github.com/openconfig/bootz/proto/bootz"
	tpb "github.com/openconfig/bootz/proto/test"
	cpb "github.com/openconfig/bootz/server/proto/config"
)

// InMemoryChassisManager provides a simple in memory handler for chassis.
type InMemoryChassisManager struct {
	chassis map[string]*cpb.Chassis
	// subscriberChannel is used to fetch bootstrap status when in test mode.
	subscriberChannel chan *bpb.ReportStatusRequest
}

// ResolveChassis fills the chassis information based on the matched inventory.
func (m *InMemoryChassisManager) ResolveChassis(ctx context.Context, chassis *types.Chassis) error {
	if chassis == nil {
		return fmt.Errorf("chassis cannot be nil")
	}
	found, ok := m.chassis[chassis.ActiveSerial]
	if !ok {
		return fmt.Errorf("chassis with serial number %v not found", chassis.ActiveSerial)
	}
	chassis.Hostname = found.GetHostname()
	chassis.BootMode = found.GetBootMode()
	chassis.StreamingSupported = found.GetStreamingSupported()
	chassis.Manufacturer = found.GetManufacturer()
	chassis.SkipIDevIDSerialValidation = found.GetSkipIdevidSerialValidation()
	return nil
}

// GenerateBootstrapData generates the bootstrap data responses for the provided serial numbers.
func (m *InMemoryChassisManager) GenerateBootstrapData(ctx context.Context, _ *types.Chassis, serials []string) ([]*bpb.BootstrapDataResponse, error) {
	responses := make([]*bpb.BootstrapDataResponse, len(serials))
	for i, serial := range serials {
		found, ok := m.chassis[serial]
		if !ok {
			return nil, fmt.Errorf("chassis with serial number %v not found", serial)
		}
		responses[i] = &bpb.BootstrapDataResponse{
			SerialNum:        serial,
			IntendedImage:    found.GetIntendedImage(),
			BootPasswordHash: found.GetBootPasswordHash(),
			BootConfig:       found.GetBootConfig(),
			Credentials:      found.GetCredentials(),
			Pathz:            found.GetPathz(),
			Authz:            found.GetAuthz(),
			CertzProfiles:    found.GetCertzProfiles(),
		}
	}
	return responses, nil
}

// UpdateStatus updates the status for each control card on the chassis.
func (m *InMemoryChassisManager) UpdateStatus(ctx context.Context, req *bpb.ReportStatusRequest) error {
	if len(req.GetStates()) == 0 {
		return fmt.Errorf("no control card or fixed chassis states provided")
	}
	// We only do the logging.
	log.Infof("Bootstrap Status: %v: Status message: %v", req.GetStatus(), req.GetStatusMessage())
	for _, v := range req.GetStates() {
		log.Infof("Control card %v changed status to %v", v.GetSerialNumber(), v.GetStatus())
	}
	// When in test mode, we only expect one single bootstrapping.
	if m.subscriberChannel != nil {
		switch req.GetStatus() {
		case bpb.ReportStatusRequest_BOOTSTRAP_STATUS_SUCCESS, bpb.ReportStatusRequest_BOOTSTRAP_STATUS_FAILURE:
			select {
			case m.subscriberChannel <- req:
			default:
				log.Warningf("Channel is full, dropping status update: %v", req.GetStatus())
			}
		}
	}
	return nil
}

// Subscribe implements the Subscribe RPC.
func (m *InMemoryChassisManager) Subscribe(req *tpb.SubscribeRequest, stream tpb.Test_SubscribeServer) error {
	if m.subscriberChannel == nil {
		return status.Errorf(codes.FailedPrecondition, "Subscribe is only supported in test mode")
	}
	select {
	case sta := <-m.subscriberChannel:
		return stream.Send(sta)
	case <-stream.Context().Done():
		return stream.Context().Err()
	}
}

// New returns a new in-memory chassis manager.
func New(config *cpb.Config) *InMemoryChassisManager {
	// For fast lookup, we build a map indexed by the control card serial number, which means modular chassis with dual control cards are indexed twice.
	chassis := make(map[string]*cpb.Chassis)
	for _, c := range config.GetChassis() {
		for _, cc := range c.GetControlCards() {
			chassis[cc.GetSerialNumber()] = c
		}
	}
	var subscriberChannel chan *bpb.ReportStatusRequest
	// If test mode is enabled, we create a valid channel for fetching status.
	if config.GetTestMode() {
		subscriberChannel = make(chan *bpb.ReportStatusRequest, 1)
	}
	return &InMemoryChassisManager{
		chassis:           chassis,
		subscriberChannel: subscriberChannel,
	}
}
