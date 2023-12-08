# Bootz Server Design
*Last updated 5 Dec 2023*

## Overview
Bootz is a new standard introduced to define a structured data format to take a device from a factory state to a fully production supportable state. The overall design of bootz is meant to allow operators of equipment to provide a data-only bootstrap request and allow vendors the freedom to implement the intent based on their own internal APIs.

## Objective
The server is being built in 3 stages:

* **Open source reference implementation**
 + Demonstrates the sequence of exchanges that occur between the network device and bootz server with mocked out implementation details
 + The reference implementation is imported directly into Google and the main server business logic code is re-used by the production Bootz server
* **Phase 1 (MVP)**
 + Build a Bootz server which provides basic bootstrap data (default credentials, software image and startup config).
* **Phase 2**
 + Extends on phase 1 to provide TPM enrollment, attestation, namespace support and gNSI support

## High Level Design
Refer to README for API flow.
![alt text](https://github.com/openconfig/bootz/blob/main/design_images/sequence_diagram.png)

At a high level, the Bootz server is a gRPC server that exposes two RPCs:
* GetBootstrapData
* ReportStatus
Devices call these gRPCs once they’re available on Google’s network to bootstrap themselves into a manageable state.

## Code Architecture
Our goal is for the internal Bootz implementation to share as much code with the open source reference implementation as possible. To achieve this, we have a platform-agnostic Bootz library which is hosted on GitHub that provides common functionality to both the reference implementation and the internal implementation. It’s then regularly synced to Google internally. Downstream dependencies of Bootz server will have interfaces defined in this library so that vendors and Google can plug in their own implementations. Vendors are encouraged to align their client code with the reference implementation where possible to mitigate failures during testing.

![alt text](https://github.com/openconfig/bootz/blob/main/design_images/venn_diagram.png)

service is the primary library that will be shared between implementations. It defines the gRPC service and has an interface for an EntityManager. This EntityManager contains the methods needed to fetch and process data from sources outside the Bootz server e.g. cryptographic secret storage, config generators. The Google internal server layer imports the service  package and is responsible for initialization of the server and the actual handling of gRPC requests.

## Source of Truth
In keeping with the existing OpenConfig setup, we opt for having GitHub as the source of truth and having regular syncs that push code to Google internally. This approach means we can accept contributions from vendors, Googlers and even community contributions in the future.

## Language
The project is written in Go.

## Reference Implementation Style Requirements For Contributors
**License Headers**
Add license headers to any files that can be added to (i.e. anything that takes the format of a source file and supports file comments). This would include things like YAML files.

```go
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
```

**Protos**
Generated protocol buffer packages must be renamed to remove underscores from their names, and their aliases must have a pb suffix.

```go
import (
   fspb "path/to/package/foo_service_go_proto" 
)
```

**Comments**
Documentation comments should always be complete sentences, and as such should always be capitalized and punctuated. Simple end-of-line comments (especially for struct fields) can be simple phrases that assume the field name is the subject.

```go
// Server handles serving quotes from the collected works of Shakespeare.
type Server struct {
    WelcomeMessage  string // displayed when user logs in
    ProtocolVersion string // checked against incoming requests
    PageLength      int    // lines per page when printing
}
```

Once comments have been addressed, make sure to click on “Resolve conversation” to let your reviewer know.
