package gnmi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type tlsTestCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTLSTestCA(t *testing.T, cn string) *tlsTestCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	ski := sha1.Sum(pub)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          ski[:],
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &tlsTestCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (ca *tlsTestCA) issue(t *testing.T, cn string, serial int64, usage x509.ExtKeyUsage) (certPEM, keyPEM []byte, cert tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if cert, err = tls.X509KeyPair(certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	return certPEM, keyPEM, cert
}

func (ca *tlsTestCA) writeCRL(t *testing.T, path string, serials ...int64) {
	t.Helper()
	tmpl := &x509.RevocationList{
		Number:     big.NewInt(time.Now().UnixNano()),
		ThisUpdate: time.Now().Add(-time.Minute),
		NextUpdate: time.Now().Add(time.Hour),
	}
	for _, s := range serials {
		tmpl.RevokedCertificateEntries = append(tmpl.RevokedCertificateEntries,
			x509.RevocationListEntry{SerialNumber: big.NewInt(s), RevocationTime: time.Now()})
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, ca.cert, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	writeTLSTestFile(t, path, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}))
}

func writeTLSTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

// newRotatingTLSTestConfig provisions configured server credentials and a
// client CA the way the telemetry launch script does.
func newRotatingTLSTestConfig(t *testing.T) (*Config, *tlsTestCA) {
	t.Helper()
	dir := t.TempDir()
	ca := newTLSTestCA(t, "test-ca")
	certPEM, keyPEM, _ := ca.issue(t, "server-v1", 2, x509.ExtKeyUsageServerAuth)
	cfg := &Config{
		SrvCertFile:   filepath.Join(dir, "server.pem"),
		SrvKeyFile:    filepath.Join(dir, "server.key"),
		CaCertFile:    filepath.Join(dir, "ca.pem"),
		SrvCertLnk:    filepath.Join(dir, "server_cert.lnk"),
		SrvKeyLnk:     filepath.Join(dir, "server_key.lnk"),
		CaCertLnk:     filepath.Join(dir, "ca_cert.lnk"),
		CertCRLConfig: filepath.Join(dir, "mtls"),
	}
	writeTLSTestFile(t, cfg.SrvCertFile, certPEM)
	writeTLSTestFile(t, cfg.SrvKeyFile, keyPEM)
	writeTLSTestFile(t, cfg.CaCertFile, ca.pem)
	return cfg, ca
}

func rotateTLSTestServerCert(t *testing.T, cfg *Config, ca *tlsTestCA, cn string) {
	t.Helper()
	certPEM, keyPEM, _ := ca.issue(t, cn, 3, x509.ExtKeyUsageServerAuth)
	dir := filepath.Dir(cfg.SrvCertLnk)
	cert := filepath.Join(dir, "gnxi_"+cn+"_1_cert.pem")
	key := filepath.Join(dir, "gnxi_"+cn+"_1_key.pem")
	writeTLSTestFile(t, cert, certPEM)
	writeTLSTestFile(t, key, keyPEM)
	muPath.Lock()
	defer muPath.Unlock()
	if err := atomicSetSrvCertKeyPair(cfg, defaultProfile, cert, key); err != nil {
		t.Fatal(err)
	}
}

func servedTLSConfig(t *testing.T, tlsCfg *tls.Config) *tls.Config {
	t.Helper()
	served, err := tlsCfg.GetConfigForClient(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("GetConfigForClient: %v", err)
	}
	return served
}

func servedTLSCN(t *testing.T, tlsCfg *tls.Config) string {
	t.Helper()
	leaf, err := x509.ParseCertificate(servedTLSConfig(t, tlsCfg).Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf.Subject.CommonName
}

func tlsTestPool(ca *tlsTestCA) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	return pool
}

// tlsTestHandshake runs a real handshake against srvCfg and returns the
// server's verdict, which with TLS 1.3 the client only learns later.
func tlsTestHandshake(t *testing.T, srvCfg *tls.Config, roots *x509.CertPool, clientCert *tls.Certificate) error {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", srvCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srvErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			srvErr <- err
			return
		}
		defer conn.Close()
		srvErr <- conn.(*tls.Conn).Handshake()
	}()
	clientCfg := &tls.Config{RootCAs: roots, ServerName: "localhost"}
	if clientCert != nil {
		// Present the certificate even when the server does not list its
		// issuer as acceptable.
		clientCfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return clientCert, nil
		}
	}
	conn, clientErr := tls.Dial("tcp", ln.Addr().String(), clientCfg)
	if clientErr == nil {
		defer conn.Close()
	}
	return errors.Join(<-srvErr, clientErr)
}

func TestRotatingTLSConfigServesRotation(t *testing.T) {
	cfg, ca := newRotatingTLSTestConfig(t)
	tlsCfg, err := RotatingTLSConfig(cfg, serverTLSBase(cfg))
	if err != nil {
		t.Fatalf("RotatingTLSConfig: %v", err)
	}
	if cn := servedTLSCN(t, tlsCfg); cn != "server-v1" {
		t.Fatalf("served %q before rotation, want server-v1", cn)
	}

	rotateTLSTestServerCert(t, cfg, ca, "server-v2")
	if cn := servedTLSCN(t, tlsCfg); cn != "server-v2" {
		t.Fatalf("served %q after rotation, want server-v2", cn)
	}

	ca2 := newTLSTestCA(t, "test-ca-v2")
	bundle := filepath.Join(filepath.Dir(cfg.CaCertLnk), "ca_gnxi_v2_1_bundle.pem")
	writeTLSTestFile(t, bundle, ca2.pem)
	muPath.Lock()
	err = atomicSetCACert(cfg, defaultProfile, bundle)
	muPath.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if !servedTLSConfig(t, tlsCfg).ClientCAs.Equal(tlsTestPool(ca2)) {
		t.Fatal("client CAs are not the rotated trust bundle")
	}
}

func TestRotatingTLSConfigKeepsRotationAcrossRestart(t *testing.T) {
	cfg, ca := newRotatingTLSTestConfig(t)
	if _, err := RotatingTLSConfig(cfg, serverTLSBase(cfg)); err != nil {
		t.Fatalf("RotatingTLSConfig: %v", err)
	}
	rotateTLSTestServerCert(t, cfg, ca, "server-v2")

	tlsCfg, err := RotatingTLSConfig(cfg, serverTLSBase(cfg))
	if err != nil {
		t.Fatalf("RotatingTLSConfig after restart: %v", err)
	}
	if cn := servedTLSCN(t, tlsCfg); cn != "server-v2" {
		t.Fatalf("served %q after restart, want the rotated server-v2", cn)
	}
}

func TestRotatingTLSConfigClientAuth(t *testing.T) {
	cfg, ca := newRotatingTLSTestConfig(t)
	_, _, trusted := ca.issue(t, "client", 10, x509.ExtKeyUsageClientAuth)
	_, _, untrusted := newTLSTestCA(t, "other-ca").issue(t, "client", 10, x509.ExtKeyUsageClientAuth)

	tests := []struct {
		name        string
		allowNoCert bool
		clientCert  *tls.Certificate
		wantErr     bool
	}{
		{name: "certificate required, none presented", wantErr: true},
		{name: "certificate required, trusted", clientCert: &trusted},
		{name: "certificate required, untrusted", clientCert: &untrusted, wantErr: true},
		{name: "certificate optional, none presented", allowNoCert: true},
		{name: "certificate optional, trusted", allowNoCert: true, clientCert: &trusted},
		{name: "certificate optional, untrusted", allowNoCert: true, clientCert: &untrusted, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg.AllowNoClientCert = tt.allowNoCert
			tlsCfg, err := RotatingTLSConfig(cfg, serverTLSBase(cfg))
			if err != nil {
				t.Fatalf("RotatingTLSConfig: %v", err)
			}
			err = tlsTestHandshake(t, tlsCfg, tlsTestPool(ca), tt.clientCert)
			if (err != nil) != tt.wantErr {
				t.Fatalf("handshake error = %v, want error %v", err, tt.wantErr)
			}
		})
	}
}

func TestRotatingTLSConfigRevokedClient(t *testing.T) {
	cfg, ca := newRotatingTLSTestConfig(t)
	_, _, revoked := ca.issue(t, "revoked", 10, x509.ExtKeyUsageClientAuth)
	_, _, valid := ca.issue(t, "valid", 11, x509.ExtKeyUsageClientAuth)
	tlsCfg, err := RotatingTLSConfig(cfg, serverTLSBase(cfg))
	if err != nil {
		t.Fatalf("RotatingTLSConfig: %v", err)
	}
	crlDir := getLinkPaths(cfg, defaultProfile).CRL

	if err := tlsTestHandshake(t, tlsCfg, tlsTestPool(ca), &revoked); err != nil {
		t.Fatalf("handshake without a CRL: %v", err)
	}

	// A CRL with the issuer's name but not its signature is ignored.
	newTLSTestCA(t, "test-ca").writeCRL(t, filepath.Join(crlDir, "forged.crl"), 10)
	if err := tlsTestHandshake(t, tlsCfg, tlsTestPool(ca), &revoked); err != nil {
		t.Fatalf("handshake with a forged CRL: %v", err)
	}

	ca.writeCRL(t, filepath.Join(crlDir, "ca.crl"), 10)
	if err := tlsTestHandshake(t, tlsCfg, tlsTestPool(ca), &revoked); !errors.Is(err, errClientCertRevoked) {
		t.Fatalf("revoked client certificate: handshake error = %v, want %v", err, errClientCertRevoked)
	}
	if err := tlsTestHandshake(t, tlsCfg, tlsTestPool(ca), &valid); err != nil {
		t.Fatalf("unrevoked client certificate: %v", err)
	}
}

func TestServerTLSBase(t *testing.T) {
	tests := []struct {
		name        string
		caCert      string
		allowNoCert bool
		want        tls.ClientAuthType
	}{
		{name: "no CA", want: tls.NoClientCert},
		{name: "no CA, certificate optional", allowNoCert: true, want: tls.NoClientCert},
		{name: "CA", caCert: "ca.pem", want: tls.RequireAndVerifyClientCert},
		{name: "CA, certificate optional", caCert: "ca.pem", allowNoCert: true, want: tls.VerifyClientCertIfGiven},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := serverTLSBase(&Config{CaCertFile: tt.caCert, AllowNoClientCert: tt.allowNoCert})
			if base.ClientAuth != tt.want {
				t.Errorf("ClientAuth = %v, want %v", base.ClientAuth, tt.want)
			}
			if !base.SessionTicketsDisabled {
				t.Error("session tickets are enabled")
			}
		})
	}
}

func TestRotatingTLSConfigErrors(t *testing.T) {
	t.Run("missing server key", func(t *testing.T) {
		cfg, _ := newRotatingTLSTestConfig(t)
		cfg.SrvKeyFile = filepath.Join(t.TempDir(), "missing.key")
		if _, err := RotatingTLSConfig(cfg, serverTLSBase(cfg)); err == nil {
			t.Fatal("RotatingTLSConfig succeeded without a server key")
		}
	})
	t.Run("missing CA", func(t *testing.T) {
		cfg, _ := newRotatingTLSTestConfig(t)
		cfg.CaCertFile = filepath.Join(t.TempDir(), "missing.pem")
		if _, err := RotatingTLSConfig(cfg, serverTLSBase(cfg)); err == nil {
			t.Fatal("RotatingTLSConfig succeeded without the CA")
		}
	})
	t.Run("invalid CA", func(t *testing.T) {
		cfg, _ := newRotatingTLSTestConfig(t)
		writeTLSTestFile(t, cfg.CaCertFile, []byte("not a certificate"))
		if _, err := RotatingTLSConfig(cfg, serverTLSBase(cfg)); err == nil {
			t.Fatal("RotatingTLSConfig succeeded with an invalid CA")
		}
	})
}
