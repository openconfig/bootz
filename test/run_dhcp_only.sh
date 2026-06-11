#!/usr/bin/env bash
set -e
DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)

go build -o "${DIR}/../dhcp/main/dhcp" "${DIR}/../dhcp/main/dhcp.go"
# DHCP service binding needs root privilege.
sudo "${DIR}/../dhcp/main/dhcp" --alsologtostderr --dhcp_file="${DIR}/config/dhcp_config.textproto"
