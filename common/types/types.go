package types

import (
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"

	epb "github.com/openconfig/attestz/proto/tpm_enrollz"
	bpb "github.com/openconfig/bootz/proto/bootz"
	apb "github.com/openconfig/gnsi/authz"
)

// OVList is a mapping of control card serial number to ownership voucher.
type OVList map[string][]byte

// SecurityArtifacts contains all KeyPairs and OVs needed for the Bootz Server.
// Currently, RSA is the only encryption standard supported by these artifacts.
type SecurityArtifacts struct {
	// The Ownership Certificate is an x509 certificate/private key pair signed by the PDC.
	// The certificate is presented to the device during bootstrapping and is used to validate the Ownership Voucher.
	OwnerCert           *x509.Certificate
	OwnerCertPrivateKey crypto.PrivateKey
	// The Pinned Domain Certificate is an x509 certificate/private key pair which acts as a certificate authority on the owner's side.
	// This certificate is included in OVs.
	PDC           *x509.Certificate
	PDCPrivateKey crypto.PrivateKey
	// The Vendor CA represents a certificate authority on the vendor side. This CA signs Ownership Vouchers which are verified by the device.
	VendorCA           *x509.Certificate
	VendorCAPrivateKey crypto.PrivateKey
	// The Trust Anchor is a self signed CA used to generate the TLS certificate.
	TrustAnchor           *x509.Certificate
	TrustAnchorPrivateKey crypto.PrivateKey
	// Ownership Vouchers are a list of PKCS7 messages signed by the Vendor CA. There is one per control card.
	OV OVList
	// The TLSKeypair is a TLS certificate used to secure connections between device and server. It is derived from the Trust Anchor.
	TLSKeypair *tls.Certificate
}

// EntityLookup is used to resolve the fields of an active control card to a chassis.
// For fixed form factor devices, the active control card is the chassis itself.
type EntityLookup struct {
	// The manufacturer of this control card or chassis.
	Manufacturer string
	// The serial number of this control card or chassis.
	SerialNumber string
	// The hardware model/part number of this control card or chassis.
	PartNumber string
	// The reported IP address of the management interface for this control
	// card or chassis.
	IPAddress string
	// The identity presented by the device.
	Identity *bpb.Identity
}

// Chassis describes a chassis that has been resolved from an organization's inventory.
type Chassis struct {
	// The intended hostname of the chassis.
	Hostname string
	// The mode this chassis should boot into.
	BootMode bpb.BootMode
	// The intended software image to install on the device.
	SoftwareImage *bpb.SoftwareImage
	// The realm this chassis exists in, typically lab or prod.
	Realm string
	// The manufacturer of this chassis.
	Manufacturer string
	// The part number of this chassis.
	PartNumber string
	// The serial number of this chassis.
	Serial string
	// Describes the control cards that exist in this chassis.
	ControlCards []*ControlCard
	// The below fields are normally unset and are primarily used for
	// cases where this data should be hardcoded e.g. for testing.
	BootConfig             *bpb.BootConfig
	Authz                  *apb.UploadRequest
	BootloaderPasswordHash string
	// Whether the device supports streaming Bootz.
	StreamingSupported bool
	// The public key owned by the device.
	PubKey *rsa.PublicKey
	// The type of public key (EK or PPK) owned by the device.
	PubKeyType epb.Key
}

// ControlCard describes a control card that exists in a resolved Chassis.
type ControlCard struct {
	Manufacturer string
	PartNumber   string
	Serial       string
}
