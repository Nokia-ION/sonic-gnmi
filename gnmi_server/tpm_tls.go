package gnmi

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"

	log "github.com/golang/glog"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

// tpmTLSEnabled reports whether the listener can present a certificate whose
// private key never leaves the TPM: the IDevID before enrollment, and the
// owner-issued oIDevID that enrollz installs for the same key.
func tpmTLSEnabled(cfg *Config) bool {
	return cfg.TPMPath != "" && cfg.TPMKeyHandle != 0
}

// loadServingKeyPair loads the identity certificate a profile presents. A
// profile without a key file is backed by the TPM key when TPM TLS is enabled.
func loadServingKeyPair(cfg *Config, certPath, keyPath string) (tls.Certificate, error) {
	if tpmTLSEnabled(cfg) {
		if _, err := os.Stat(keyPath); errors.Is(err, os.ErrNotExist) {
			return loadTPMKeyPair(cfg, certPath)
		}
	}
	return tls.LoadX509KeyPair(certPath, keyPath)
}

// linkExists reports whether path exists, without following a symlink.
func linkExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func loadTPMKeyPair(cfg *Config, certPath string) (tls.Certificate, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return tls.Certificate{}, err
	}
	var chain [][]byte
	for rest := data; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			chain = append(chain, block.Bytes)
		}
	}
	if len(chain) == 0 {
		return tls.Certificate{}, fmt.Errorf("no certificate found in %s", certPath)
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse %s: %w", certPath, err)
	}
	cert := tls.Certificate{
		Certificate: chain,
		Leaf:        leaf,
		PrivateKey: &tpmSigner{
			path:   cfg.TPMPath,
			handle: tpm2.TPMHandle(cfg.TPMKeyHandle),
			pub:    leaf.PublicKey,
		},
	}
	// TPM ECC keys are commonly bound to the hash matching their curve, so
	// TLS 1.2 must not pick another one.
	if k, ok := leaf.PublicKey.(*ecdsa.PublicKey); ok {
		switch k.Curve {
		case elliptic.P256():
			cert.SupportedSignatureAlgorithms = []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256}
		case elliptic.P384():
			cert.SupportedSignatureAlgorithms = []tls.SignatureScheme{tls.ECDSAWithP384AndSHA384}
		case elliptic.P521():
			cert.SupportedSignatureAlgorithms = []tls.SignatureScheme{tls.ECDSAWithP521AndSHA512}
		}
	}
	return cert, nil
}

// tpmSigner signs TLS handshakes with a persistent TPM key. It opens the TPM
// for each signature so that no handle is held between connections.
type tpmSigner struct {
	path   string
	handle tpm2.TPMHandle
	pub    crypto.PublicKey
}

func (s *tpmSigner) Public() crypto.PublicKey {
	return s.pub
}

func (s *tpmSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	t, err := linuxtpm.Open(s.path)
	if err != nil {
		return nil, fmt.Errorf("open TPM %s: %w", s.path, err)
	}
	defer t.Close()

	rp, err := tpm2.ReadPublic{ObjectHandle: s.handle}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("read TPM key 0x%08X: %w", uint32(s.handle), err)
	}
	pub, err := rp.OutPublic.Contents()
	if err != nil {
		return nil, err
	}
	tpmPub, err := tpm2.Pub(*pub)
	if err != nil {
		return nil, err
	}
	if k, ok := s.pub.(interface{ Equal(crypto.PublicKey) bool }); !ok || !k.Equal(tpmPub) {
		return nil, fmt.Errorf("certificate public key does not match TPM key 0x%08X", uint32(s.handle))
	}

	hashAlg, err := tpmHashAlg(opts.HashFunc())
	if err != nil {
		return nil, err
	}
	var schemeAlg tpm2.TPMAlgID
	switch pub.Type {
	case tpm2.TPMAlgECC:
		schemeAlg = tpm2.TPMAlgECDSA
	case tpm2.TPMAlgRSA:
		schemeAlg = tpm2.TPMAlgRSASSA
		if _, ok := opts.(*rsa.PSSOptions); ok {
			schemeAlg = tpm2.TPMAlgRSAPSS
		}
	default:
		return nil, fmt.Errorf("unsupported TPM key type 0x%x", pub.Type)
	}

	rsp, err := tpm2.Sign{
		KeyHandle: tpm2.NamedHandle{Handle: s.handle, Name: rp.Name},
		Digest:    tpm2.TPM2BDigest{Buffer: digest},
		InScheme: tpm2.TPMTSigScheme{
			Scheme:  schemeAlg,
			Details: tpm2.NewTPMUSigScheme(schemeAlg, &tpm2.TPMSSchemeHash{HashAlg: hashAlg}),
		},
		Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck, Hierarchy: tpm2.TPMRHNull},
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("TPM sign with key 0x%08X: %w", uint32(s.handle), err)
	}

	switch schemeAlg {
	case tpm2.TPMAlgECDSA:
		sig, err := rsp.Signature.Signature.ECDSA()
		if err != nil {
			return nil, err
		}
		return asn1.Marshal(struct{ R, S *big.Int }{
			new(big.Int).SetBytes(sig.SignatureR.Buffer),
			new(big.Int).SetBytes(sig.SignatureS.Buffer),
		})
	case tpm2.TPMAlgRSAPSS:
		sig, err := rsp.Signature.Signature.RSAPSS()
		if err != nil {
			return nil, err
		}
		return sig.Sig.Buffer, nil
	default:
		sig, err := rsp.Signature.Signature.RSASSA()
		if err != nil {
			return nil, err
		}
		return sig.Sig.Buffer, nil
	}
}

func tpmHashAlg(h crypto.Hash) (tpm2.TPMAlgID, error) {
	switch h {
	case crypto.SHA256:
		return tpm2.TPMAlgSHA256, nil
	case crypto.SHA384:
		return tpm2.TPMAlgSHA384, nil
	case crypto.SHA512:
		return tpm2.TPMAlgSHA512, nil
	default:
		return 0, fmt.Errorf("unsupported hash %v for TPM signing", h)
	}
}

// readIdentityCert returns a factory identity certificate as PEM. The file
// takes precedence; without one, the certificate is read from its TPM NV index.
func readIdentityCert(cfg *Config, path string, nvIndex uint32) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err == nil || !errors.Is(err, os.ErrNotExist) || cfg.TPMPath == "" || nvIndex == 0 {
		return data, err
	}
	t, err := linuxtpm.Open(cfg.TPMPath)
	if err != nil {
		return nil, fmt.Errorf("open TPM %s: %w", cfg.TPMPath, err)
	}
	defer t.Close()
	nv, err := readNVIndex(t, nvIndex)
	if err != nil {
		return nil, fmt.Errorf("read %s from TPM NV index 0x%08X: %w", filepath.Base(path), nvIndex, err)
	}
	// An NV index may be larger than the DER certificate it holds.
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(nv, &raw); err != nil {
		return nil, fmt.Errorf("TPM NV index 0x%08X does not hold a certificate: %w", nvIndex, err)
	}
	der := raw.FullBytes
	if _, err := x509.ParseCertificate(der); err != nil {
		return nil, fmt.Errorf("TPM NV index 0x%08X does not hold a certificate: %w", nvIndex, err)
	}
	log.V(2).Infof("read %s from TPM NV index 0x%08X", filepath.Base(path), nvIndex)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// readNVIndex reads a whole NV index, in chunks no larger than the TPM allows.
func readNVIndex(t transport.TPM, index uint32) ([]byte, error) {
	pubRsp, err := tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(index)}.Execute(t)
	if err != nil {
		return nil, err
	}
	nvPub, err := pubRsp.NVPublic.Contents()
	if err != nil {
		return nil, err
	}
	capRsp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTNVBufferMax),
		PropertyCount: 1,
	}.Execute(t)
	if err != nil {
		return nil, err
	}
	props, err := capRsp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return nil, err
	}
	if len(props.TPMProperty) == 0 || props.TPMProperty[0].Value == 0 {
		return nil, fmt.Errorf("TPM did not report its NV buffer size")
	}
	maxBuf := int(props.TPMProperty[0].Value)

	size := int(nvPub.DataSize)
	data := make([]byte, 0, size)
	for len(data) < size {
		chunk := min(size-len(data), maxBuf)
		rsp, err := tpm2.NVRead{
			AuthHandle: tpm2.AuthHandle{
				Handle: tpm2.TPMHandle(index),
				Name:   pubRsp.NVName,
				Auth:   tpm2.PasswordAuth(nil),
			},
			NVIndex: tpm2.NamedHandle{Handle: tpm2.TPMHandle(index), Name: pubRsp.NVName},
			Size:    uint16(chunk),
			Offset:  uint16(len(data)),
		}.Execute(t)
		if err != nil {
			return nil, fmt.Errorf("NV read at offset %d: %w", len(data), err)
		}
		data = append(data, rsp.Data.Buffer...)
	}
	return data, nil
}
