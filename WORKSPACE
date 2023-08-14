load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

### Bazel rules for many languages to compile PROTO into gRPC libraries
# Note: any version of this which is less than 4.3.0 requires bazel version 5.4.0 (set in .bazelversion file)
http_archive(
    name = "rules_proto_grpc",
    sha256 = "fb7fc7a3c19a92b2f15ed7c4ffb2983e956625c1436f57a3430b897ba9864059",
    strip_prefix = "rules_proto_grpc-4.3.0",
    urls = ["https://github.com/rules-proto-grpc/rules_proto_grpc/archive/4.3.0.tar.gz"],
)

# googleapis has not had a release since 2016 - take the master version as of 4-jan-23
http_archive(
    name = "com_google_googleapis",
    sha256 = "9fc03150d86501d7da35eefa989d5553bdd77a95cfe4373cdafe8eee92f6bfb1",
    strip_prefix = "googleapis-870a5ed7e141b4faf70e2a0858854e9b5bb18612",
    urls = ["https://github.com/googleapis/googleapis/archive/870a5ed7e141b4faf70e2a0858854e9b5bb18612.tar.gz"],
)

load("@com_google_googleapis//:repository_rules.bzl", "switched_rules_by_language")

switched_rules_by_language(
    name = "com_google_googleapis_imports",
    cc = True,
    go = True,
)

load(
    "@rules_proto_grpc//:repositories.bzl",
    "bazel_gazelle",
    "io_bazel_rules_go",
    "rules_proto_grpc_repos",
    "rules_proto_grpc_toolchains",
)

rules_proto_grpc_toolchains()

rules_proto_grpc_repos()

load("@rules_proto//proto:repositories.bzl", "rules_proto_dependencies", "rules_proto_toolchains")

rules_proto_dependencies()

rules_proto_toolchains()

### Golang
io_bazel_rules_go()

load("@io_bazel_rules_go//go:deps.bzl", "go_register_toolchains", "go_rules_dependencies")

go_rules_dependencies()

go_register_toolchains(go_version = "1.19")

# gazelle:repo bazel_gazelle
bazel_gazelle()

load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies")


local_repository(
  name = "local_repo_root",
  path = "./",
)

load("@rules_proto_grpc//go:repositories.bzl", rules_proto_grpc_go_repos = "go_repos")
load("//:deps.bzl", "go_dependencies")

# gazelle:repository_macro deps.bzl%go_dependencies
go_dependencies()

rules_proto_grpc_go_repos()

# Load gazelle_dependencies last, so that the newer version of org_golang_google_grpc is used.
# see https://github.com/rules-proto-grpc/rules_proto_grpc/issues/160
gazelle_dependencies()

load("@com_github_grpc_grpc//bazel:grpc_deps.bzl", "grpc_deps")

grpc_deps()
