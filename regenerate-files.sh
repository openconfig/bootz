#!/bin/bash
set -euo pipefail

BASE=$(bazelisk  info bazel-genfiles)
BOOTZ_NS='github.com/openconfig/bootz/proto'
ENTITY_NS='github.com/openconfig/bootz/server/entitymanager/proto'

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

bazelisk build //proto:all
# first args in the package name, second arg is namespace for the package, and thrid is the location where the generated will be saved. 
copy_generated "bootz"  ${BOOTZ_NS}   "proto/"
copy_generated "entity"  ${ENTITY_NS} "server/entitymanager/proto/"  

