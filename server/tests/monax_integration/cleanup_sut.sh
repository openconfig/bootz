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

# Force purge all lingering SUT resources from the Kind cluster default namespace.

echo "========================================================"
# 1. Delete deployment and services
echo "Deleting bootz-sut deployments and services..."
kubectl delete deployment bootz-sut --ignore-not-found=true
kubectl delete service bootz-sut --ignore-not-found=true

# 2. Force delete ConfigMaps (avoiding garbage collection delays)
echo "Purging bootz-sut ConfigMaps..."
kubectl delete configmap bootz-sut --ignore-not-found=true --grace-period=0 --force

# 3. Wait for resources to be fully expunged
echo "Waiting for resource cleanup to settle..."
sleep 5

echo "Active default namespace resources:"
kubectl get all
echo "========================================================"
echo "Cleanup complete. Ready to start SUT."