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

# If you try to build this Dockerfile manually, make sure you build from the repo root directory.

#checkov:skip=CKV_DOCKER_2

FROM golang:1.26 AS builder
WORKDIR /app
COPY . .
RUN chmod -R o+r ./test/config/
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o ./out/bootz ./server/emulator

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=builder /app/out/bootz ./bootz
COPY --from=builder /app/test/config/bootz_config.textproto ./bootz_config.textproto
USER nonroot
EXPOSE 15006/tcp
ENTRYPOINT ["/app/bootz"]
CMD ["--alsologtostderr", "--config_file=/app/bootz_config.textproto"]  
