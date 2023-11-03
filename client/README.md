# Bootz Client Reference emulation

The code located in this directory is intended to emulate a typical Bootz
client. Where appropriate, some device-specific functions such as downloading
and image or applying a config are mocked out and are simply logged.

## Usage

First, make sure the server is running. See [server readme](../server/README.md).

To run the client, build it and then run using the below commands. Use --alsologtostderr to get verbose logs on the terminal.

```shell
cd client
go build client.go
./client -alsologtostderr
```

### Flags

* `port`: The port to listen to the Bootz Server on localhost. Defaults to the standard Bootz port of 15006.
* `insecure_boot`: Whether to set start the emulated client in an insecure
  boot mode, in which ownership voucher and certificates aren't checked.