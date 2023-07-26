# Bootz Client Emulator

The code located in this directory is intended to emulator a typical Bootz client. Where appropriate, some device-specific functions such as downloading and image or applying a config are mocked out and are simply logged.

## Usage

### Flags

*   `port`: The port to listen to the Bootz Server on localhost.
*   `boot_mode`: Determines the the mode to start the client emulator in. If set to `SecureOnly`, ownership vouchers and ownership certificate will be verified.
*   `root_ca_cert_path`: A path to a file that contains a PEM encoded certificate for the trusted ZTP Signing authority. This certificate will be used to validate the ownership voucher.

### Root CA

Included in this directory is a file named `ca.pem`. This file should contain the PEM encoded certificate that the device will use to validate ownership vouchers.