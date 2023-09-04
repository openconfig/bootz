# Copyright 2023 Google LLC
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

load("@io_bazel_rules_go//proto:compiler.bzl", "go_proto_compiler")
load("@io_bazel_rules_go//proto/wkt:well_known_types.bzl", "PROTO_RUNTIME_DEPS", "WELL_KNOWN_TYPES_APIV2")

def use_new_compilers():
    go_proto_compiler(
        name = "go_protoc_gen_go",
        options = [
            "paths=source_relative",
        ],
        plugin = "@org_golang_google_protobuf//cmd/protoc-gen-go",
        suffix = ".pb.go",
        visibility = ["//visibility:public"],
        deps = PROTO_RUNTIME_DEPS + WELL_KNOWN_TYPES_APIV2,
    )
    go_proto_compiler(
        name = "go_protoc_gen_go_grpc",
        options = [
            "paths=source_relative",
        ],
        plugin = "@org_golang_google_grpc_cmd_protoc_gen_go_grpc//:protoc-gen-go-grpc",
        suffix = "_grpc.pb.go",
        visibility = ["//visibility:public"],
        deps = PROTO_RUNTIME_DEPS + [
            "@org_golang_google_grpc//:go_default_library",
            "@org_golang_google_grpc//codes:go_default_library",
            "@org_golang_google_grpc//status:go_default_library",
        ],
    )