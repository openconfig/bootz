# Bootz Client Reference emulation

The code located in this directory is intended to emulate a typical Bootz client of TPM 2.0 with IDevID.
The IDevID cert/key, if not provided, will be generated dynamically from the default test vendor CA cert.
The IDevID signing procedure is emulated in software without using a TPM chip.
Where appropriate, some device-specific functions such as upgrading image and applying config are mocked out
as loggings only.

## Usage

First, make sure the server is running. See [server readme](../server/README.md).

To run the client, build it and then run using the below commands. Use --alsologtostderr to get verbose logs on the terminal.

```shell
cd client
go build client.go
./client -alsologtostderr
```

### Flags

- `port`: The Bootz server port to connect to on localhost. Defaults to the standard Bootz port of 15006.
- `streaming`: Whether to use the streaming bootstrap RPC. Defaults to false.
- `insecure_boot`: Whether to set the emulated client in an insecure boot mode, in which ownership voucher and
  ownership certificate aren't checked. Defaults to false.
