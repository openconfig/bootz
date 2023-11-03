# Bootz Server Reference Implementation

The code located in this directory is intended to emulate a typical Bootz
server.

## Usage

To run the server, build it and then run using the below commands. Use --alsologtostderr to get verbose logs on the terminal.

```shell
cd server
go build server.go
./server -alsologtostderr
```

Once running, run the client implementation in another terminal. See [client readme](../client/README.md).

### Flags

* `port`: The port to start to the Bootz Server on localhost. Defaults to 15006 which is the standard Bootz port.
* `generate_ovs_for`: A comma-separated list of control card or chassis serial numbers to generate Ownership Vouchers for. If unset, defaults to the standard test case of using control cards "123A" and "123B".
* `inv_config`: A path to a textproto file that stores the server's inventory config.