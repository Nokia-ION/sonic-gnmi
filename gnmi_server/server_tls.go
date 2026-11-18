package gnmi

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	log "github.com/golang/glog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/tls/certprovider"
)

var errClientCertRevoked = errors.New("client certificate has been revoked")

// SrvRotatingConfig returns the gNMI/gNOI server credentials. The serving
// profile, its certificate, key and client CA bundle, and its CRLs are read
// for every new connection, so a gNSI Certz rotation or certificate-id rebind
// takes effect on the next handshake without restarting the server.
func SrvRotatingConfig(cfg *Config) ([]grpc.ServerOption, []certprovider.Provider, error) {
	tlsCfg, err := RotatingTLSConfig(cfg, serverTLSBase(cfg))
	if err != nil {
		return nil, nil, err
	}
	return []grpc.ServerOption{grpc.Creds(credentials.NewTLS(tlsCfg))}, nil, nil
}

// serverTLSBase returns the settings shared by every handshake. Without a CA
// no client certificate is requested. With one, a client certificate is
// required unless AllowNoClientCert is set; any certificate a client presents
// is verified either way.
func serverTLSBase(cfg *Config) *tls.Config {
	clientAuth := tls.NoClientCert
	if cfg.CaCertFile != "" {
		clientAuth = tls.RequireAndVerifyClientCert
		if cfg.AllowNoClientCert {
			clientAuth = tls.VerifyClientCertIfGiven
		}
	}
	return &tls.Config{
		ClientAuth: clientAuth,
		MinVersion: tls.VersionTLS12,
		// The FIPS OpenSSL crypto backend has no AES-CTR, which crypto/tls
		// uses to encrypt session tickets; issuing one panics the server.
		SessionTicketsDisabled:   true,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}
}

// RotatingTLSConfig returns a copy of base whose every handshake is served
// from the profile servingProfilePaths picks at that moment. The certificate,
// the client CA bundle and the CRLs all come from that one choice.
func RotatingTLSConfig(cfg *Config, base *tls.Config) (*tls.Config, error) {
	if err := linkServingCerts(cfg); err != nil {
		return nil, err
	}
	if _, err := servingTLSConfig(cfg, base); err != nil {
		return nil, err
	}
	tlsCfg := base.Clone()
	tlsCfg.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		return servingTLSConfig(cfg, base)
	}
	return tlsCfg, nil
}

func servingTLSConfig(cfg *Config, base *tls.Config) (*tls.Config, error) {
	muPath.RLock()
	defer muPath.RUnlock()

	paths := servingProfilePaths(cfg)
	cert, err := loadServingKeyPair(cfg, paths.Cert, paths.Key)
	if err != nil {
		return nil, fmt.Errorf("could not load server key pair: %v", err)
	}
	tlsCfg := base.Clone()
	tlsCfg.Certificates = []tls.Certificate{cert}
	tlsCfg.GetConfigForClient = nil
	if cfg.CaCertFile == "" {
		return tlsCfg, nil
	}
	if tlsCfg.ClientCAs, err = readCertPool(paths.CA); err != nil {
		return nil, err
	}
	if cfg.CertCRLConfig != "" {
		tlsCfg.VerifyConnection = func(cs tls.ConnectionState) error {
			return checkRevocation(paths.CRL, cs.VerifiedChains)
		}
	}
	return tlsCfg, nil
}

// linkServingCerts points the default profile's links at the configured
// certificates, unless a gNSI Certz rotation is in effect, so that a rotation
// survives restarts while a changed configuration still takes effect.
func linkServingCerts(cfg *Config) error {
	// Ensure link paths are not empty before OS operations. This prevents
	// os.Stat("") or os.Symlink("", ...) from crashing.
	if cfg.CaCertLnk == "" {
		cfg.CaCertLnk = "/keys/ca_cert.lnk"
	}
	if cfg.SrvCertLnk == "" {
		cfg.SrvCertLnk = "/keys/server_cert.lnk"
	}
	if cfg.SrvKeyLnk == "" {
		cfg.SrvKeyLnk = "/keys/server_key.lnk"
	}
	muPath.Lock()
	defer muPath.Unlock()

	log.V(1).Infof("Setting server credentials using: %v; %v; %v; %v; %v; %v;", cfg.CaCertLnk, cfg.CaCertFile, cfg.SrvCertLnk, cfg.SrvCertFile, cfg.SrvKeyLnk, cfg.SrvKeyFile)
	// CA Certificate Check. Link the configured CA on start unless a gNSI
	// Certz rotation is currently in effect (then keep the rotated bundle so
	// it survives restarts). This lets a changed config CA take effect and
	// heals stale non-rotation links.
	if cfg.CaCertFile != "" {
		if _, err := os.Stat(cfg.CaCertFile); err != nil {
			return fmt.Errorf("CA certificate file not found: %v", err)
		}
		if !symlinkPointsToRotation(cfg.CaCertLnk) {
			atomicSetCACert(cfg, defaultProfile, cfg.CaCertFile)
		}
	} else {
		log.V(1).Infof("CaCertFile is empty; client certificate verification will be disabled.")
	}
	// Server Certificate & Key Check (Mandatory for TLS). Same policy: (re)link
	// the configured server cert/key on start unless a Certz rotation is in
	// effect for both links. Certz rotates the pair together, so we treat them
	// as a unit.
	// The enrollz oIDevID is served with the TPM key and has no key link.
	certTarget, _ := os.Readlink(cfg.SrvCertLnk)
	tpmRotation := tpmTLSEnabled(cfg) && symlinkPointsToRotation(cfg.SrvCertLnk) &&
		filepath.Base(certTarget) == oIDevIDCertName
	_, keyErr := os.Stat(cfg.SrvKeyFile)
	switch {
	case tpmRotation:
		if _, err := rmSymlink(cfg.SrvKeyLnk); err != nil {
			return fmt.Errorf("remove stale server key link: %v", err)
		}
		log.V(1).Infof("Serving TPM-backed %s with TPM key 0x%08X", certTarget, cfg.TPMKeyHandle)
	case !symlinkPointsToRotation(cfg.SrvCertLnk) && tpmTLSEnabled(cfg) && cfg.SrvCertFile != "" &&
		(cfg.SrvKeyFile == "" || errors.Is(keyErr, os.ErrNotExist)):
		// No key file: the configured certificate is the IDevID, whose key
		// is in the TPM.
		if _, err := os.Stat(cfg.SrvCertFile); err != nil {
			return fmt.Errorf("server certificate file stat error: %v", err)
		}
		if err := atomicSetSrvCertTPMSigner(cfg, cfg.SrvCertFile); err != nil {
			return err
		}
		log.V(1).Infof("Serving %s with TPM key 0x%08X", cfg.SrvCertFile, cfg.TPMKeyHandle)
	case !symlinkPointsToRotation(cfg.SrvCertLnk) || !symlinkPointsToRotation(cfg.SrvKeyLnk):
		if cfg.SrvCertFile == "" || cfg.SrvKeyFile == "" {
			// No configured material to (re)link. Fall back to any existing
			// valid symlinks; only fail if there is nothing usable to serve.
			if !isSymlinkValid(cfg.SrvCertLnk) || !isSymlinkValid(cfg.SrvKeyLnk) {
				return fmt.Errorf("server certificate or key file path is empty")
			}
		} else {
			if _, err := os.Stat(cfg.SrvCertFile); err != nil {
				return fmt.Errorf("server certificate file stat error: %v", err)
			}
			if _, err := os.Stat(cfg.SrvKeyFile); err != nil {
				return fmt.Errorf("server key file stat error: %v", err)
			}
			atomicSetSrvCertKeyPair(cfg, defaultProfile, cfg.SrvCertFile, cfg.SrvKeyFile)
		}
	}
	return nil
}

// checkRevocation rejects a client only when every verified chain has a
// certificate revoked by a CRL in dir. A certificate whose issuer has no CRL
// there, or whose CRL cannot be verified, does not fail the handshake; client
// revocation is also checked at the application layer.
func checkRevocation(dir string, chains [][]*x509.Certificate) error {
	if len(chains) == 0 {
		return nil
	}
	crls := readCRLs(dir)
	if len(crls) == 0 {
		return nil
	}
	for _, chain := range chains {
		if !chainRevoked(chain, crls) {
			return nil
		}
	}
	return errClientCertRevoked
}

func readCRLs(dir string) []*x509.RevocationList {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.V(1).Infof("Cannot read CRL directory %s: %v", dir, err)
		}
		return nil
	}
	var crls []*x509.RevocationList
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		path := filepath.Join(dir, e.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			log.V(1).Infof("Cannot read CRL %s: %v", path, err)
			continue
		}
		if block, _ := pem.Decode(raw); block != nil && block.Type == "X509 CRL" {
			raw = block.Bytes
		}
		crl, err := x509.ParseRevocationList(raw)
		if err != nil {
			log.V(1).Infof("Cannot parse CRL %s: %v", path, err)
			continue
		}
		crls = append(crls, crl)
	}
	return crls
}

func chainRevoked(chain []*x509.Certificate, crls []*x509.RevocationList) bool {
	for _, c := range chain {
		for _, crl := range crls {
			if bytes.Equal(crl.RawIssuer, c.RawIssuer) && crlSignedInChain(crl, chain) && crlRevokes(crl, c) {
				return true
			}
		}
	}
	return false
}

// crlSignedInChain verifies crl with the chain certificate that issued it,
// matched by subject and key identifier as RFC 5280 section 5.2.1 requires.
func crlSignedInChain(crl *x509.RevocationList, chain []*x509.Certificate) bool {
	for _, c := range chain {
		if !bytes.Equal(c.RawSubject, crl.RawIssuer) || !bytes.Equal(c.SubjectKeyId, crl.AuthorityKeyId) {
			continue
		}
		if c.KeyUsage != 0 && c.KeyUsage&x509.KeyUsageCRLSign == 0 {
			return false
		}
		return crl.CheckSignatureFrom(c) == nil
	}
	return false
}

func crlRevokes(crl *x509.RevocationList, c *x509.Certificate) bool {
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(c.SerialNumber) == 0 {
			return true
		}
	}
	return false
}
