#!/bin/bash

# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Run the bootz services test in an existing Kubernetes cluster.

readonly SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
readonly BOOTZ_DIR="$( cd -- "${SCRIPT_DIR}/../../.." &> /dev/null && pwd )"
readonly MONAX_DIR="$( cd -- "${BOOTZ_DIR}/../monax" &> /dev/null && pwd )"

function build_and_load_image() {
  local name=$1
  local dockerfile=$2
  
  echo "Building image ${name}..."
  if ! docker build \
      --file "${BOOTZ_DIR}/${dockerfile}" \
      --tag "${name}:latest" \
      "${BOOTZ_DIR}/.."; then
    echo "Could not build ${name}" >&2
    exit 1
  fi
  
  echo "Loading image ${name} into kind cluster ${KIND_CLUSTER}..."
  if ! kind load docker-image "${name}:latest" --name "${KIND_CLUSTER}"; then
    echo "Could not load ${name} into cluster ${KIND_CLUSTER}" >&2
    exit 1
  fi
}

function run_test() {
  # Run the test from Bootz root directory to ensure local package imports resolve correctly.
  cd "${BOOTZ_DIR}"
  GOROOT= go test -v server/tests/monax_integration/bootz_test.go \
    --abstract_sut="${BOOTZ_DIR}/server/tests/monax_integration/abstract_sut.txtpb" \
    --library="${BOOTZ_DIR}/server/tests/monax_integration/kubernetes_library.txtpb" \
    --runtime_parameters="${BOOTZ_DIR}/server/tests/monax_integration/kubernetes_runtime_parame
ters.txtpb" \
    --alsologtostderr
}

function main() {
  if [[ -z "${KIND_CLUSTER}" ]]; then
    echo "Error: KIND_CLUSTER is not set." >&2
    echo "Please set 'KIND_CLUSTER=your_kind_cluster_name' before running this script." >&2
    exit 1
  fi

  build_and_load_image "bootz-sut" "Dockerfile.sut"

  run_test
}

main "$@"