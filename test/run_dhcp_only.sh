#!/usr/bin/env bash
set -e
go build -o ../dhcp/main/dhcp ../dhcp/main/dhcp.go
sudo -s ../dhcp/main/dhcp --alsologtostderr --dhcp_file=./config/dhcp_config.textproto
