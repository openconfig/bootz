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
