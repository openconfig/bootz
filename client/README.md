# Bootz Client Reference emulation

The code located in this directory is intended to emulate a typical Bootz
client. Where appropriate, some device-specific functions such as downloading
and image or applying a config are mocked out and are simply logged.

## Usage

First, make sure the server is running. See [server readme](../server/README.md).

To run the client, build it and then run it with at least the `port` flag specified. The default value of `root_ca_cert_path` works for this implementation. We recommend using the flag `alsologtostderr` to get a verbose output.

```shell
cd client
go build client.go
./client -port 8080 -alsologtostderr
```

### Flags

* `port`: The port to listen to the Bootz Server on localhost.
* `insecure_boot`: Whether to set start the emulated client in an insecure
  boot mode, in which ownership voucher and certificates aren't checked.
* `root_ca_cert_path`: A path to a file that contains a PEM encoded
  certificate for the trusted ZTP Signing authority. This certificate will be
  used to validate the ownership voucher.
