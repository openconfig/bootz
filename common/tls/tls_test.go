package tls

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	ownercertificate "github.com/openconfig/bootz/common/owner_certificate"
)

func selfSignedTLSCert(t *testing.T) *tls.Certificate {
	selfSignedCA, selfSignedCAPriv, err := ownercertificate.NewRSACertificate("Self Signed CA", "", nil, nil)
	if err != nil {
		t.Fatalf("unable to generate test self signed CA: %v", err)
	}
	return &tls.Certificate{
		Certificate: [][]byte{selfSignedCA.Raw},
		PrivateKey:  selfSignedCAPriv,
	}
}

func validIDevIDTLSCert(t *testing.T, iDevIDCA *x509.Certificate, iDevIDCAPriv crypto.PrivateKey) *tls.Certificate {
	vendorIDevID, vendorIDevIDPriv, err := ownercertificate.NewRSACertificate("Vendor IDevID", "1234", iDevIDCA, iDevIDCAPriv)
	if err != nil {
		t.Fatalf("unable to generate test IDevID: %v", err)
	}
	return &tls.Certificate{
		PrivateKey:  vendorIDevIDPriv,
		Certificate: [][]byte{vendorIDevID.Raw},
	}
}

func TestTLSConfiguration(t *testing.T) {
	ca, caPriv, err := ownercertificate.NewRSACertificate("Bootz Trust Anchor CA", "", nil, nil)
	if err != nil {
		t.Fatalf("unable to generate test trust anchor CA: %v", err)
	}

	iDevIDCA, iDevIDCAPriv, err := ownercertificate.NewRSACertificate("Vendor IDevID Root CA", "", nil, nil)
	if err != nil {
		t.Fatalf("unable to generate test IDevID CA: %v", err)
	}

	iDevIDPool := x509.NewCertPool()
	iDevIDPool.AddCert(iDevIDCA)

	opts := &Opts{
		CAPrivateKey: caPriv,
		CACert:       ca,
		IPAddress:    net.ParseIP("::1"),
		ClientCAs:    iDevIDPool,
		ServerCertSubject: &pkix.Name{
			Organization: []string{"Google"},
			Country:      []string{"US"},
			Province:     []string{"CA"},
			Locality:     []string{"Mountain View"},
			CommonName:   "Bootz Server TLS Certificate ",
		},
	}

	conf, err := TLSConfiguration(opts)
	if err != nil {
		t.Errorf("TLSConfiguration failed: %v", err)
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = conf
	server.StartTLS()
	defer server.Close()

	tests := []struct {
		name            string
		clientTLSConfig *tls.Config
		wantErr         bool
	}{
		{
			name: "Valid IDevID cert in TLS handshake succeeds (legacy Bootz)",
			clientTLSConfig: &tls.Config{
				GetClientCertificate: func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
					return validIDevIDTLSCert(t, iDevIDCA, iDevIDCAPriv), nil
				},
				InsecureSkipVerify: true,
				ServerName:         "::1",
			},
		},
		{
			name: "Self-signed cert in TLS handshake fails (legacy Bootz)",
			clientTLSConfig: &tls.Config{
				GetClientCertificate: func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
					return selfSignedTLSCert(t), nil
				},
				InsecureSkipVerify: true,
				ServerName:         "::1",
			},
			wantErr: true,
		},
		{
			name: "No cert in TLS handshake succeeds (BootstrapStream)",
			clientTLSConfig: &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         "::1",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: test.clientTLSConfig,
				},
			}
			resp, err := client.Get(server.URL)
			if err != nil {
				if test.wantErr {
					return
				}
				t.Fatalf("Client failed to connect to test server: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Errorf("Expected status OK (200), got %v", resp.StatusCode)
			}
		})
	}
}
