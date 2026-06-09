#!/bin/bash
set -euo pipefail

BASE=$(bazel info bazel-genfiles)
BOOTZ_NS='github.com/openconfig/bootz/proto'
CONFIG_NS='github.com/openconfig/bootz/server/proto'
DHCPCONFIG_NS='github.com/openconfig/bootz/dhcp/proto'

copy_generated() {
	pkg="$1"
	# Default to using package name for proto if $4 is unset
	proto="$1" && [ "${4++}" ] && proto="$4"
	# Bazel go_rules will create empty files containing "// +build ignore\n\npackage ignore"
	# in the case where the protoc compiler doesn't generate any output. See:
	# https://github.com/bazelbuild/rules_go/blob/03a8b8e90eebe699d7/go/tools/builders/protoc.go#L190
	for file in "${BASE}""/${3}""${proto}"_go_proto_/"${2}"/"${pkg}"/*.pb.go; do
		[[ $(head -n 1 "${file}") == "// +build ignore" ]] || cp -f "${file}" "${3}${pkg}/"
	done
}

bazel build //proto:all
bazel build //server/proto:all
bazel build //dhcp/proto:all
# first arg is the package name, second arg is namespace for the package, and third is the location where the generated code will be saved.
copy_generated "bootz" ${BOOTZ_NS} "proto/"
copy_generated "config" ${CONFIG_NS} "server/proto/"
copy_generated "dhcpconfig" ${DHCPCONFIG_NS} "dhcp/proto/"
