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

// Package sutstate holds the shared state for the monolithic SUT emulator.
package sutstate

import (
	"sync"

	bootzpb "github.com/openconfig/bootz/proto/bootz"
	testpb "github.com/openconfig/bootz/server/tests/proto/test"
)

var (
	mu                sync.RWMutex
	softwareImage     *bootzpb.SoftwareImage
	bootstrapData     *testpb.BootstrapData
	securityArtifacts *testpb.SecurityArtifacts
	recoveryData      *testpb.DUTRecoveryData
)

// SetSoftwareImage sets the active software image.
func SetSoftwareImage(img *bootzpb.SoftwareImage) {
	mu.Lock()
	defer mu.Unlock()
	softwareImage = img
}

// GetSoftwareImage returns the active software image.
func GetSoftwareImage() *bootzpb.SoftwareImage {
	mu.RLock()
	defer mu.RUnlock()
	return softwareImage
}

// SetBootstrapData sets the active bootstrap data.
func SetBootstrapData(data *testpb.BootstrapData) {
	mu.Lock()
	defer mu.Unlock()
	bootstrapData = data
}

// GetBootstrapData returns the active bootstrap data.
func GetBootstrapData() *testpb.BootstrapData {
	mu.RLock()
	defer mu.RUnlock()
	return bootstrapData
}

// SetSecurityArtifacts sets the active security artifacts.
func SetSecurityArtifacts(sa *testpb.SecurityArtifacts) {
	mu.Lock()
	defer mu.Unlock()
	securityArtifacts = sa
}

// GetSecurityArtifacts returns the active security artifacts.
func GetSecurityArtifacts() *testpb.SecurityArtifacts {
	mu.RLock()
	defer mu.RUnlock()
	return securityArtifacts
}

// SetRecoveryData sets the active recovery data.
func SetRecoveryData(data *testpb.DUTRecoveryData) {
	mu.Lock()
	defer mu.Unlock()
	recoveryData = data
}

// GetRecoveryData returns the active recovery data.
func GetRecoveryData() *testpb.DUTRecoveryData {
	mu.RLock()
	defer mu.RUnlock()
	return recoveryData
}