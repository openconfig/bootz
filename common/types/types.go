// Copyright 2026 Google LLC
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

package types

import (
	bpb "github.com/openconfig/bootz/proto/bootz"
)

// Chassis describes a chassis that has been resolved from an organization's inventory.
type Chassis struct {
	// All the serial numbers that need bootstrapping for this chassis.
	// For fixed form factor devices, it only contains the serial number of this chassis itself.
	// For modular devices, it contains the serial numbers of all control cards in this chassis.
	Serials []string
	// The active serial number that sent the bootstrap request.
	ActiveSerial string
	// The reported IP address of the management interface that sent the bootstrap request.
	IPAddress string
	// The identity presented by this chassis.
	Identity *bpb.Identity

	// ================================================================================
	// All the fields above are initialized from device bootstrap request.
	// All the fields below are resolved from Bootz server inventory.
	// ================================================================================

	// The intended hostname of the chassis.
	Hostname string
	// The mode this chassis should boot into.
	BootMode bpb.BootMode
	// Whether the device supports streaming Bootz.
	StreamingSupported bool
	// The intended software image to install on the device.
	SoftwareImage *bpb.SoftwareImage
	// The realm this chassis exists in, typically lab or prod.
	Realm string
	// The manufacturer of this chassis.
	Manufacturer string
	// The part number of this chassis.
	PartNumber string
	// Whether to skip IDevID serial number validation for this chassis.
	SkipIDevIDSerialValidation bool
}
