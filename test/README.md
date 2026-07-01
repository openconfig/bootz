# Test Bootz with Real Switch Chassis

The files located in this directory are intended to test Bootz with real switch
chassis of your choice.

## Prerequisite

- A DUT (Device Under Test). This is the switch chassis of your choice, which
  must be running an image that supports Bootz protocol.

- A PC with an Ethernet port, running Linux operating system. This PC will be
  the host running the SUTs (Services Under Test), which are Bootz service, HTTP
  service, and optionally DHCP service.
  - Bootz service: Listens on TCP port 15006.
  - HTTP service: Listens on TCP port 8080.
  - DHCP service: Listens on UDP port 67 and UDP port 547.

We provide two methods to run the Bootz test.

- Bare Metal Manual Test Method

  Run all SUTs on bare metal (i.e. run all SUTs natively on the host PC), and
  start the Bootz process on the DUT manually.

- Monax Auto Test Method

  Run most SUTs inside Monax virtual Kubernetes cluster containers (when
  possible), and start the Bootz process on the DUT automatically by calling
  the vendor implemented `dut.StartBootz()` function.

  NOTE: DHCP service has to run on bare metal anyway, because KIND
  does not support layer 2 traffic.

## Bare Metal Manual Test Method

### Bare Metal Setup (a one-time effort)

1. Configure the PC with a static IP address shown below.

   `10.0.0.1/24`.

2. Modify the contents of the files below with the info of your switch chassis.
   The instructions are provided inside the files themselves.
   - [./config/bootz_config.textproto](./config/bootz_config.textproto)
   - [./config/dhcp_config.textproto](./config/dhcp_config.textproto)

   NOTE: If you configured the PC with a different static IP and/or different
   subnet in Step 1, you must also change the referenced IPs and subnets in the
   files above accordingly.

### Bare Metal Run

You can choose to test the DHCP Bootz flow or the DHCP-less Bootz flow.

#### Bare Metal DHCP Bootz Flow

1. Run the Bash script below to build and start the services (Bootz, HTTP,
   DHCP).

   `./run_bootz_with_http_and_dhcp.sh`

   NOTE: DHCP service needs root privilege to bind to the Ethernet interface.

2. Connect the management port of your switch chassis to the Ethernet port of
   the PC.

3. Put your switch chassis into DHCP Bootz ZeroTouch mode to begin the testing.

#### Bare Metal DHCP-less Bootz Flow

1. Run the Bash script below to build and start the services (Bootz, HTTP).

   `./run_bootz_with_http.sh`

2. Configure the management interface of your switch chassis with a static IP
   from the same subnet of the PC.

3. Connect the management port of your switch chassis to the Ethernet port of
   the PC.

4. Run the DHCP-less Bootz commands on your switch chassis to begin the testing.

### Bare Metal Cleanup

1. After you finish the testing, press `Ctrl+C` on the PC to stop the services.

## Monax Auto Test Method

### Monax Setup (a one-time effort)

1. Install [Docker](https://www.docker.com/) and
   [KIND (Kubernetes IN Docker)](https://kind.sigs.k8s.io/) on the PC.

2. Configure the PC with a static IP address shown below.

   `10.0.0.1/24`.

3. Modify the contents of the files below with the info of your switch chassis.
   The instructions are provided inside the files themselves.
   - [./config/bootz_config.textproto](./config/bootz_config.textproto)
   - [./config/dhcp_config.textproto](./config/dhcp_config.textproto)

   NOTE: If you configured the PC with a different static IP and/or different
   subnet in Step 2, you must also change the referenced IPs and subnets in the
   files above accordingly.

4. Implement the `StartBootz()` function in file [./dut/dut.go](./dut/dut.go) to control your
   switch chassis under test.

   NOTE: Since this function is completely vendor-specific, you can keep your
   implementation private for your own tests only. You don't need to submit
   or publish your implementation on GitHub.

### Monax Prepare

1. Delete all existing KIND virtual clusters from the PC, if any.

   `kind delete clusters -A`

2. Create a new KIND virtual cluster from the given config. NOTE: You **MUST**
   use the config provided.

   `kind create cluster --config=./sut/kind_config.yaml`

### Monax Run

You can choose to test the DHCP Bootz flow or the DHCP-less Bootz flow.

#### Monax DHCP Bootz Flow

1. Connect the management port of your switch chassis to the Ethernet port of
   the PC.

2. Run the Bash script below in a terminal to build and start the DHCP
   service.

   `./run_dhcp_only.sh`

   NOTE: DHCP service needs root privilege to bind to the Ethernet interface.

3. Run the command below in another terminal to build the Monax SUTs
   (Bootz, HTTP), then `dut.StartBootz()` function will be called to start the
   testing automatically.

   `go run monax_bootz.go --alsologtostderr --dhcp`

#### Monax DHCP-less Bootz Flow

1. Configure the management interface of your switch chassis with a static IP
   from the same subnet of the PC.

2. Connect the management port of your switch chassis to the Ethernet port of
   the PC.

3. Run the command below in a terminal to build the Monax SUTs (Bootz, HTTP),
   then `dut.StartBootz()` function will be called to start the testing
   automatically.

   `go run monax_bootz.go --alsologtostderr`

### Monax Cleanup

1. After you finish the testing, press `Ctrl+C` on the PC to stop the Monax
   SUTs.

2. In the other terminal where you ran the DHCP Bash script, press `Ctrl+C` to
   stop the DHCP service.

3. Run the following command to delete the KIND virtual cluster.

   `kind delete clusters -A`

   NOTE: If you plan to run more testing later, then you can skip deleting the
   cluster so that next time you don't need to create it again before the
   testing.
