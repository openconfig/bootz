# Bootz Client Reference emulation

The code located in this directory is intended to emulate a typical Bootz client of TPM 2.0 with IDevID.
Both the Bootz server address and the information of the chassis it emulates are read from the config file.
Where appropriate, some device-specific functions such as upgrading image and applying config are mocked out as loggings only.

## Usage

First, make sure the server is running. See [server readme](../server/emulator/README.md).

To run the client, build it and then run using the below commands. Use `--alsologtostderr` to get verbose logs on the terminal.

```shell
go build client.go
./client --alsologtostderr
```

### Flags

- `--config_file`: The config file to read from. Defaults to "../testdata/bootz_config.textproto".
- `--streaming`: Whether to use the streaming bootstrap RPC. Defaults to false.
- `--insecure_boot`: Whether to set the emulated client in an insecure boot mode, in which ownership voucher and
  ownership certificate aren't checked. Defaults to false.
