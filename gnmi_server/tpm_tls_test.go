package gnmi

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadServingKeyPair_TPMBackedWhenKeyMissing(t *testing.T) {
	km := newTestTpmKeyMaterial(t)
	cfg := newTestConfig(t)
	cfg.TPMKeyHandle = 0x81820000
	writeKeyMaterial(t, cfg.IakCertFile, cfg.IDevIDCertFile, km)

	cert, err := loadServingKeyPair(cfg, cfg.IDevIDCertFile, filepath.Join(t.TempDir(), "missing.key"))
	if err != nil {
		t.Fatalf("loadServingKeyPair: %v", err)
	}
	signer, ok := cert.PrivateKey.(*tpmSigner)
	if !ok {
		t.Fatalf("private key: got %T, want *tpmSigner", cert.PrivateKey)
	}
	if signer.handle != 0x81820000 || !km.idevidKey.PublicKey.Equal(signer.Public()) {
		t.Errorf("signer: handle 0x%08X, public key does not match the certificate", uint32(signer.handle))
	}
}

func TestLoadServingKeyPair_KeyFileRequiredWithoutTPM(t *testing.T) {
	km := newTestTpmKeyMaterial(t)
	cfg := newTestConfig(t)
	writeKeyMaterial(t, cfg.IakCertFile, cfg.IDevIDCertFile, km)

	if _, err := loadServingKeyPair(cfg, cfg.IDevIDCertFile, filepath.Join(t.TempDir(), "missing.key")); err == nil {
		t.Fatal("loadServingKeyPair: want an error without a key file and TPM key handle")
	}
}

func TestReadIdentityCert_FilePrecedesNV(t *testing.T) {
	km := newTestTpmKeyMaterial(t)
	cfg := newTestConfig(t)
	cfg.TPMPath = filepath.Join(t.TempDir(), "no-tpm")
	writeKeyMaterial(t, cfg.IakCertFile, cfg.IDevIDCertFile, km)

	got, err := readIdentityCert(cfg, cfg.IDevIDCertFile, 0x01C90000)
	if err != nil || string(got) != km.idevidCertPEM {
		t.Errorf("readIdentityCert: got %q, %v; want the file content", got, err)
	}
	if err := os.Remove(cfg.IDevIDCertFile); err != nil {
		t.Fatal(err)
	}
	if _, err := readIdentityCert(cfg, cfg.IDevIDCertFile, 0x01C90000); err == nil {
		t.Error("readIdentityCert: want an error when neither the file nor the TPM is available")
	}
}
