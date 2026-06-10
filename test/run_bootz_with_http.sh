#!/usr/bin/env bash
set -e
go build -o ../server/emulator/main ../server/emulator/main.go
../server/emulator/main --alsologtostderr --config_file=./config/bootz_config.textproto --http_address=:8080 --http_folder=./www/
