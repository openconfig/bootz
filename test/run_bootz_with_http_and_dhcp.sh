#!/usr/bin/env bash
set -e
DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)

go build -o "${DIR}/../server/emulator/main" "${DIR}/../server/emulator/main.go"
# DHCP service binding needs root privilege.
sudo "${DIR}/../server/emulator/main" --alsologtostderr --config_file="${DIR}/config/bootz_config.textproto" --http_address=:8080 --http_folder="${DIR}/www/" --dhcp_file="${DIR}/config/dhcp_config.textproto"
