// Package tls contains helper functions for generating Bootz server TLS configurations.
package tls

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"time"

	log "github.com/golang/glog"
)

// Opts define all parameters needed to generate a Bootz server TLS config.
type Opts struct {
	// The private key of the CA that will sign the server's TLS certificate.
	CAPrivateKey crypto.PrivateKey
	// The certificate of the CA that will be used to generate the server's TLS cert.
	CACert *x509.Certificate
	// The IP address of the server. This will be used to generate the TLS cert.
	IPAddress net.IP
	// The x509 Cert Pool of IDevID CAs. If a client present a certificate, it must be
	// signed by one of these.
	ClientCAs *x509.CertPool
	// The server cert's subject.
	ServerCertSubject *pkix.Name
}

// LogPeerTLSCertificate prints details about the peer's TLS certificate for debugging.
func LogPeerTLSCertificate(state tls.ConnectionState) error {
	certs := state.PeerCertificates
	if len(certs) == 0 {
		log.Infof("Client provided no TLS certificates")
		return nil
	}
	log.Infof("Client provided %d TLS certificate(s)", len(certs))
	for i, cert := range certs {
		log.Infof("Cert %d:\nIssuer=%v\nSubject=%v\nSerial=%v", i, cert.Issuer.String(), cert.Subject.String(), cert.SerialNumber.String())
	}
	return nil
}

// TLSConfiguration generates a TLS config for Bootz server.
func TLSConfiguration(opts *Opts) (*tls.Config, error) {
	if opts == nil {
		return nil, fmt.Errorf("opts is nil")
	}
	if opts.CAPrivateKey == nil {
		return nil, fmt.Errorf("CAPrivateKey is nil")
	}
	if opts.CACert == nil {
		return nil, fmt.Errorf("CACert is nil")
	}
	if !opts.CACert.IsCA {
		return nil, fmt.Errorf("CACert is not a CA")
	}
	if opts.IPAddress == nil {
		return nil, fmt.Errorf("IPAddress is nil")
	}
	if opts.ClientCAs == nil {
		return nil, fmt.Errorf("ClientCAs is nil")
	}
	if opts.ServerCertSubject == nil {
		return nil, fmt.Errorf("ServerCertSubject is nil")
	}
	// 1. Generate a private key for the server.
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("unable to generate private key: %v", err)
	}
	// 2. Calculate SubjectKeyId
	pubKeyBytes := x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)
	keyHash := sha256.Sum256(pubKeyBytes)

	// 3. Create the template and cert.
	template := x509.Certificate{
		SerialNumber:   big.NewInt(int64(time.Now().Year())),
		Subject:        *opts.ServerCertSubject,
		IPAddresses:    []net.IP{opts.IPAddress},
		NotBefore:      time.Now().AddDate(0, 0, -1), // One day before server start-up.
		NotAfter:       time.Now().AddDate(11, 0, 0), // 11 years after server start-up.
		SubjectKeyId:   keyHash[:],
		AuthorityKeyId: opts.CACert.SubjectKeyId,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:       x509.KeyUsageDigitalSignature,
	}

	cert, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		opts.CACert,
		&privateKey.PublicKey,
		opts.CAPrivateKey)

	if err != nil {
		return nil, fmt.Errorf("unable to create TLS server cert: %v", err)
	}

	tlsCert := &tls.Certificate{
		PrivateKey:  privateKey,
		Certificate: [][]byte{cert},
	}

	// 4. Create the Root CAs trust bundle.
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(opts.CACert)

	// 5. Create the final TLS server config.
	return &tls.Config{
		Certificates:     []tls.Certificate{*tlsCert},
		RootCAs:          rootCAs,
		ServerName:       opts.IPAddress.String(),
		ClientCAs:        opts.ClientCAs,
		VerifyConnection: LogPeerTLSCertificate,
		ClientAuth:       tls.VerifyClientCertIfGiven,
	}, nil
}
