# Bootz Server Reference Implementation

The code located in this directory is intended to emulate a typical Bootz
server.

## Usage

To run the server, build it and then run it with at least the `port` flag specified. The default value of `artifact_dir` works for this implementation. We recommend using the flag `alsologtostderr` to get a verbose output.

```shell
cd server
go build server.go
./server -port 8080 -alsologtostderr
```

Once running, run the client implementation in another terminal. See [client readme](../client/README.md).

### Flags

* `port`: The port to start to the Bootz Server on localhost.
* `artifact_dir`: A relative directory to look for security artifacts. See README.md in the testdata directory for an explanation of these.