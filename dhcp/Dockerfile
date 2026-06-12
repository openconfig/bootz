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

FROM golang:1.26 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /bootz-dhcp ./dhcp/main

# hadolint ignore=DL3007
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /bootz-dhcp /bootz-dhcp
# DHCP needs to run as root to bind to port 67 and use raw sockets.
# hadolint ignore=DL3002
USER nonroot
ENTRYPOINT ["/bootz-dhcp"]

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD pgrep dhcp || exit 1

