#!/usr/bin/env bash
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e
DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)

go build -o "${DIR}/../server/emulator/main" "${DIR}/../server/emulator/main.go"
# DHCP service binding needs root privilege.
sudo "${DIR}/../server/emulator/main" --alsologtostderr --config_file="${DIR}/config/bootz_config.textproto" --http_address=:8080 --http_folder="${DIR}/www/" --dhcp_file="${DIR}/config/dhcp_config.textproto"
