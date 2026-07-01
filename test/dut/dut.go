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

// Package dut is completely vendor-specific, and should be implemented by each vendor themselves.
// Each vendor only needs to cover their own switch chassis they want to test, and does not need to consider compatibility with other vendors.
package dut

import (
	log "github.com/golang/glog"
)

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Please feel free to add any variables, data structures and helper functions in this file as needed to assist the StartBootz function below.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// StartBootz starts the Bootz process on the DUT. The argument dhcp indicates whether to start the DHCP Bootz (true) or DHCP-less Bootz (false).
func StartBootz(dhcp bool) error {
	var err error

	log.Infof("=============================================================================")
	log.Infof("Starting the Bootz process on the DUT (DHCP: %v)", dhcp)
	log.Infof("=============================================================================")

	// Implement the logic here to start the Bootz process on the DUT.
	// You can either use your own organization's private libraries to directly control your switch chassis via any vendor-specific APIs,
	// or employ the Ondatra library (https://github.com/openconfig/ondatra) to indirectly control your switch chassis via the connected ATE if any.

	return err
}
