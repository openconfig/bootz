# Bootz Server Reference Implementation

The code located in this directory is intended to start a typical Bootz server from command line.
All server artifacts and chassis inventories are read from the config file.

## Usage

To run the server, build it and then run using the below commands. Use `--alsologtostderr` to get verbose logs on the terminal.

```shell
go build main.go
./main --alsologtostderr
```

### Flags

- `--config_file`: The config file to read from. Defaults to "../../testdata/bootz_config.textproto".

### Containerization

The typical bootz server has also been containerized with a [bazel oci_image rule](https://github.com/bazel-contrib/rules_oci).
To load the container image into Docker:

```bash
bazel run //server/emulator:load_bootz_server_image
```

And run:

```bash
docker run --rm --user $(id -u):$(id -g) \
  -p 15006:15006 \
  -v ./testdata:/config \
  open-config-bootz-server:latest \
  --config_file=/config/bootz_config.textproto \
  --alsologtostderr
```