package gnmi

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agiledragon/gomonkey/v2"
	common_pb "github.com/openconfig/attestz/proto/common_definitions"
	enrollz_pb "github.com/openconfig/attestz/proto/tpm_enrollz"
	"google.golang.org/grpc/codes"
)

const (
	testControlCardSerial   = "TEST-CARD-0001"
	testControlCardSlot     = "1"
	testChassisManufacturer = "TEST-MANUFACTURER"
	testChassisPartNumber   = "TEST-PART-NO-123"
	testChassisSerialNumber = "TEST-CHASSIS-0001"
)

func testCardSelection() *common_pb.ControlCardSelection {
	return &common_pb.ControlCardSelection{
		ControlCardId: &common_pb.ControlCardSelection_Role{Role: common_pb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE},
	}
}

// newTestConfig creates a Config with TPM cert paths pointing into a temp directory.
func newTestConfig(t *testing.T) *Config {
	t.Helper()
	dir := t.TempDir()
	return &Config{
		TPMPath:        "/dev/tpmrm0",
		IakCertFile:    filepath.Join(dir, "iak_cert.pem"),
		IDevIDCertFile: filepath.Join(dir, "idevid_cert.pem"),
		OIakCertFile:   filepath.Join(dir, "oiak_cert.pem"),
		IakContextFile: filepath.Join(dir, "iak_context.bin"),
	}
}

// testControlCards is the hardware identity every enrollz/attestz test reports,
// pre-cached so the RPCs never reach the inventory file or STATE_DB.
func testControlCards() []*controlCardInfo {
	return []*controlCardInfo{{
		role:         common_pb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE,
		serial:       testControlCardSerial,
		slot:         testControlCardSlot,
		manufacturer: testChassisManufacturer,
		partNumber:   testChassisPartNumber,
		serialNumber: testChassisSerialNumber,
	}}
}

// newTestEnrollzServer constructs an enrollz server with pre-populated hardware
// identity and the given config.
func newTestEnrollzServer(t *testing.T, cfg *Config) *TpmEnrollzServer {
	t.Helper()
	return NewTpmEnrollzServer(&Server{
		cachedControlCards: testControlCards(),
		config:             cfg,
	})
}

// selfSignedCertPEM generates a minimal self-signed PEM certificate for key.
func selfSignedCertPEM(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("selfSignedCertPEM: create cert: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// testTpmKeyMaterial holds IAK and IDevID key/cert material for use in tests.
type testTpmKeyMaterial struct {
	iakKey         *ecdsa.PrivateKey
	iakCertPEM     string // simulates content at cfg.IakCertFile
	oiakCertPEM    string // rotated oIAK cert (different self-signed cert, same iakKey)
	idevidKey      *ecdsa.PrivateKey
	idevidCertPEM  string // simulates content at cfg.IDevIDCertFile
	oidevidCertPEM string // rotated oIDevID cert (different self-signed cert, same idevidKey)
}

func newTestTpmKeyMaterial(t *testing.T) *testTpmKeyMaterial {
	t.Helper()
	iakKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test IAK key: %v", err)
	}
	idevidKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test IDevID key: %v", err)
	}
	return &testTpmKeyMaterial{
		iakKey:         iakKey,
		iakCertPEM:     selfSignedCertPEM(t, iakKey),
		oiakCertPEM:    selfSignedCertPEM(t, iakKey),
		idevidKey:      idevidKey,
		idevidCertPEM:  selfSignedCertPEM(t, idevidKey),
		oidevidCertPEM: selfSignedCertPEM(t, idevidKey),
	}
}

// writeKeyMaterial writes iakCertPEM and idevidCertPEM to the test cert paths.
func writeKeyMaterial(t *testing.T, iakPath, idevIDPath string, km *testTpmKeyMaterial) {
	t.Helper()
	if err := os.WriteFile(iakPath, []byte(km.iakCertPEM), 0644); err != nil {
		t.Fatalf("setup: write IAK cert: %v", err)
	}
	if err := os.WriteFile(idevIDPath, []byte(km.idevidCertPEM), 0644); err != nil {
		t.Fatalf("setup: write IDevID cert: %v", err)
	}
}

// ---- resolveControlCard unit tests ------------------------------------------

func TestEnrollzResolveControlCard_BySerial_Match(t *testing.T) {
	cards := testControlCards()
	sel := &common_pb.ControlCardSelection{
		ControlCardId: &common_pb.ControlCardSelection_Serial{Serial: testControlCardSerial},
	}
	got, err := resolveControlCard(sel, cards)
	if err != nil {
		t.Fatalf("resolveControlCard returned unexpected error: %v", err)
	}
	if got != cards[0] {
		t.Errorf("resolveControlCard returned %+v, want %+v", got, cards[0])
	}
}

func TestEnrollzResolveControlCard_ByRole_Match(t *testing.T) {
	cards := testControlCards()
	got, err := resolveControlCard(testCardSelection(), cards)
	if err != nil {
		t.Fatalf("resolveControlCard returned unexpected error: %v", err)
	}
	if got != cards[0] {
		t.Errorf("resolveControlCard returned %+v, want %+v", got, cards[0])
	}
}

func TestEnrollzResolveControlCard_BySlot_Match(t *testing.T) {
	cards := testControlCards()
	sel := &common_pb.ControlCardSelection{
		ControlCardId: &common_pb.ControlCardSelection_Slot{Slot: testControlCardSlot},
	}
	got, err := resolveControlCard(sel, cards)
	if err != nil {
		t.Fatalf("resolveControlCard returned unexpected error: %v", err)
	}
	if got != cards[0] {
		t.Errorf("resolveControlCard returned %+v, want %+v", got, cards[0])
	}
}

func TestEnrollzResolveControlCard_NoMatch(t *testing.T) {
	sel := &common_pb.ControlCardSelection{
		ControlCardId: &common_pb.ControlCardSelection_Serial{Serial: "NO-SUCH-SERIAL"},
	}
	_, err := resolveControlCard(sel, testControlCards())
	testErr(err, codes.InvalidArgument, "no control card matches selection", t)
}

func TestEnrollzResolveControlCard_NoSelection(t *testing.T) {
	_, err := resolveControlCard(nil, testControlCards())
	testErr(err, codes.InvalidArgument, "control_card_selection must be specified", t)
}

func TestEnrollzResolveControlCard_MultipleCards_SelectsCorrectOne(t *testing.T) {
	standby := &controlCardInfo{
		role:   common_pb.ControlCardRole_CONTROL_CARD_ROLE_STANDBY,
		serial: "TEST-CARD-0002",
		slot:   "2",
	}
	cards := append(testControlCards(), standby)

	sel := &common_pb.ControlCardSelection{
		ControlCardId: &common_pb.ControlCardSelection_Slot{Slot: "2"},
	}
	got, err := resolveControlCard(sel, cards)
	if err != nil {
		t.Fatalf("resolveControlCard returned unexpected error: %v", err)
	}
	if got != standby {
		t.Errorf("resolveControlCard returned %+v, want the standby card %+v", got, standby)
	}
}

// ---- GetIakCert tests -------------------------------------------------------

func TestEnrollzGetIakCert_Success(t *testing.T) {
	km := newTestTpmKeyMaterial(t)
	cfg := newTestConfig(t)
	srv := newTestEnrollzServer(t, cfg)
	writeKeyMaterial(t, cfg.IakCertFile, cfg.IDevIDCertFile, km)

	resp, err := srv.GetIakCert(context.Background(), &enrollz_pb.GetIakCertRequest{
		ControlCardSelection: testCardSelection(),
	})
	if err != nil {
		t.Fatalf("GetIakCert returned unexpected error: %v", err)
	}
	if resp.GetIakCert() != km.iakCertPEM {
		t.Errorf("IakCert: got %q, want %q", resp.GetIakCert(), km.iakCertPEM)
	}
	if resp.GetIdevidCert() != km.idevidCertPEM {
		t.Errorf("IdevidCert: got %q, want %q", resp.GetIdevidCert(), km.idevidCertPEM)
	}
	if !resp.GetAtomicCertRotationSupported() {
		t.Error("AtomicCertRotationSupported: got false, want true")
	}
	id := resp.GetControlCardId()
	if id.GetControlCardSerial() != testControlCardSerial {
		t.Errorf("ControlCardSerial: got %q, want %q", id.GetControlCardSerial(), testControlCardSerial)
	}
	if id.GetControlCardSlot() != testControlCardSlot {
		t.Errorf("ControlCardSlot: got %q, want %q", id.GetControlCardSlot(), testControlCardSlot)
	}
	if id.GetChassisManufacturer() != testChassisManufacturer {
		t.Errorf("ChassisManufacturer: got %q, want %q", id.GetChassisManufacturer(), testChassisManufacturer)
	}
	if id.GetChassisPartNumber() != testChassisPartNumber {
		t.Errorf("ChassisPartNumber: got %q, want %q", id.GetChassisPartNumber(), testChassisPartNumber)
	}
	if id.GetChassisSerialNumber() != testChassisSerialNumber {
		t.Errorf("ChassisSerialNumber: got %q, want %q", id.GetChassisSerialNumber(), testChassisSerialNumber)
	}
	if id.GetControlCardRole() != common_pb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE {
		t.Errorf("ControlCardRole: got %v, want ACTIVE", id.GetControlCardRole())
	}
}

func TestEnrollzGetIakCert_NoSelection(t *testing.T) {
	srv := newTestEnrollzServer(t, newTestConfig(t))
	_, err := srv.GetIakCert(context.Background(), &enrollz_pb.GetIakCertRequest{})
	testErr(err, codes.InvalidArgument, "control_card_selection must be specified", t)
}

func TestEnrollzGetIakCert_WrongSelection(t *testing.T) {
	srv := newTestEnrollzServer(t, newTestConfig(t))
	req := &enrollz_pb.GetIakCertRequest{
		ControlCardSelection: &common_pb.ControlCardSelection{
			ControlCardId: &common_pb.ControlCardSelection_Serial{Serial: "WRONG-SERIAL"},
		},
	}
	_, err := srv.GetIakCert(context.Background(), req)
	testErr(err, codes.InvalidArgument, "no control card matches selection", t)
}

func TestEnrollzGetIakCert_MissingIakCert(t *testing.T) {
	cfg := newTestConfig(t)
	srv := newTestEnrollzServer(t, cfg)
	_, err := srv.GetIakCert(context.Background(), &enrollz_pb.GetIakCertRequest{
		ControlCardSelection: testCardSelection(),
	})
	testErr(err, codes.Internal, fmt.Sprintf("failed to read IAK cert from %s", cfg.IakCertFile), t)
}

func TestEnrollzGetIakCert_MissingIdevidCert(t *testing.T) {
	km := newTestTpmKeyMaterial(t)
	cfg := newTestConfig(t)
	srv := newTestEnrollzServer(t, cfg)
	if err := os.WriteFile(cfg.IakCertFile, []byte(km.iakCertPEM), 0644); err != nil {
		t.Fatalf("setup: write IAK cert: %v", err)
	}
	_, err := srv.GetIakCert(context.Background(), &enrollz_pb.GetIakCertRequest{
		ControlCardSelection: testCardSelection(),
	})
	testErr(err, codes.Internal, fmt.Sprintf("failed to read IDevID cert from %s", cfg.IDevIDCertFile), t)
}

// ---- RotateOIakCert request validation tests --------------------------------

func TestEnrollzRotateOIakCert_NoUpdates(t *testing.T) {
	srv := newTestEnrollzServer(t, newTestConfig(t))
	_, err := srv.RotateOIakCert(context.Background(), &enrollz_pb.RotateOIakCertRequest{})
	testErr(err, codes.InvalidArgument, "exactly one update must be provided, got 0", t)
}

func TestEnrollzRotateOIakCert_MultipleUpdates(t *testing.T) {
	srv := newTestEnrollzServer(t, newTestConfig(t))
	req := &enrollz_pb.RotateOIakCertRequest{
		Updates: []*enrollz_pb.ControlCardCertUpdate{
			{ControlCardSelection: testCardSelection(), OiakCert: "a"},
			{ControlCardSelection: testCardSelection(), OiakCert: "b"},
		},
	}
	_, err := srv.RotateOIakCert(context.Background(), req)
	testErr(err, codes.InvalidArgument, "exactly one update must be provided, got 2", t)
}

func TestEnrollzRotateOIakCert_NoSelection(t *testing.T) {
	srv := newTestEnrollzServer(t, newTestConfig(t))
	req := &enrollz_pb.RotateOIakCertRequest{
		Updates: []*enrollz_pb.ControlCardCertUpdate{{OiakCert: "oiak"}},
	}
	_, err := srv.RotateOIakCert(context.Background(), req)
	testErr(err, codes.InvalidArgument, "control_card_selection must be specified", t)
}

func TestEnrollzRotateOIakCert_WrongSelection(t *testing.T) {
	srv := newTestEnrollzServer(t, newTestConfig(t))
	req := &enrollz_pb.RotateOIakCertRequest{
		Updates: []*enrollz_pb.ControlCardCertUpdate{{
			ControlCardSelection: &common_pb.ControlCardSelection{
				ControlCardId: &common_pb.ControlCardSelection_Serial{Serial: "WRONG-SERIAL"},
			},
			OiakCert: "oiak",
		}},
	}
	_, err := srv.RotateOIakCert(context.Background(), req)
	testErr(err, codes.InvalidArgument, "no control card matches selection", t)
}

func TestEnrollzRotateOIakCert_EmptyOiakCert(t *testing.T) {
	srv := newTestEnrollzServer(t, newTestConfig(t))
	req := &enrollz_pb.RotateOIakCertRequest{
		Updates: []*enrollz_pb.ControlCardCertUpdate{{ControlCardSelection: testCardSelection()}},
	}
	_, err := srv.RotateOIakCert(context.Background(), req)
	testErr(err, codes.InvalidArgument, "oiak_cert must be provided", t)
}

func TestEnrollzRotateOIakCert_OidevidWithoutSslProfile(t *testing.T) {
	srv := newTestEnrollzServer(t, newTestConfig(t))
	req := &enrollz_pb.RotateOIakCertRequest{
		Updates: []*enrollz_pb.ControlCardCertUpdate{{
			ControlCardSelection: testCardSelection(),
			OiakCert:             "oiak",
			OidevidCert:          "oidevid",
		}},
	}
	_, err := srv.RotateOIakCert(context.Background(), req)
	testErr(err, codes.InvalidArgument, "ssl_profile_id must be provided when oidevid_cert is present", t)
}

func TestEnrollzRotateOIakCert_SslProfileWithoutOidevid(t *testing.T) {
	srv := newTestEnrollzServer(t, newTestConfig(t))
	req := &enrollz_pb.RotateOIakCertRequest{
		SslProfileId: "some-profile",
		Updates: []*enrollz_pb.ControlCardCertUpdate{{
			ControlCardSelection: testCardSelection(),
			OiakCert:             "oiak",
		}},
	}
	_, err := srv.RotateOIakCert(context.Background(), req)
	testErr(err, codes.InvalidArgument, "ssl_profile_id must not be provided without oidevid_cert", t)
}

// TestEnrollzRotateOIakCert_OidevidUnimplemented: serving an oIDevID as the
// gNxI server certificate needs the TPM-backed TLS signer, which is off
// without a TPM key handle.
func TestEnrollzRotateOIakCert_OidevidUnimplemented(t *testing.T) {
	km := newTestTpmKeyMaterial(t)
	cfg := newTestConfig(t)
	srv := newTestEnrollzServer(t, cfg)
	writeKeyMaterial(t, cfg.IakCertFile, cfg.IDevIDCertFile, km)

	req := &enrollz_pb.RotateOIakCertRequest{
		SslProfileId: "some-profile",
		Updates: []*enrollz_pb.ControlCardCertUpdate{{
			ControlCardSelection: testCardSelection(),
			OiakCert:             km.oiakCertPEM,
			OidevidCert:          km.oidevidCertPEM,
		}},
	}
	_, err := srv.RotateOIakCert(context.Background(), req)
	testErr(err, codes.Unimplemented, "oIDevID rotation requires a TPM-backed TLS signer", t)

	// The oIAK cert must not have been written either: the request is rejected
	// as a whole so the caller can retry once support lands.
	if _, err := os.Stat(cfg.OIakCertFile); !os.IsNotExist(err) {
		t.Error("oIAK cert should not be written when the request is rejected")
	}
}

// newTestTPMServingConfig adds a TPM key handle and a default profile served
// from the IDevID certificate with no key link, as SrvAdvConfig leaves it.
func newTestTPMServingConfig(t *testing.T, km *testTpmKeyMaterial) *Config {
	t.Helper()
	cfg := newTestConfig(t)
	dir := filepath.Dir(cfg.IakCertFile)
	cfg.TPMKeyHandle = 0x81820000
	cfg.SrvCertLnk = filepath.Join(dir, "server.crt")
	cfg.SrvKeyLnk = filepath.Join(dir, "server.key")
	writeKeyMaterial(t, cfg.IakCertFile, cfg.IDevIDCertFile, km)
	if err := os.Symlink(cfg.IDevIDCertFile, cfg.SrvCertLnk); err != nil {
		t.Fatalf("setup: link server cert: %v", err)
	}
	return cfg
}

func TestEnrollzRotateOIakCert_OidevidInstallsTPMBackedCert(t *testing.T) {
	km := newTestTpmKeyMaterial(t)
	cfg := newTestTPMServingConfig(t, km)
	srv := newTestEnrollzServer(t, cfg)

	req := &enrollz_pb.RotateOIakCertRequest{
		SslProfileId: defaultProfile,
		Updates: []*enrollz_pb.ControlCardCertUpdate{{
			ControlCardSelection: testCardSelection(),
			OiakCert:             km.oiakCertPEM,
			OidevidCert:          km.oidevidCertPEM,
		}},
	}
	if _, err := srv.RotateOIakCert(context.Background(), req); err != nil {
		t.Fatalf("RotateOIakCert returned unexpected error: %v", err)
	}

	certPath := filepath.Join(filepath.Dir(cfg.SrvCertLnk), oIDevIDCertName)
	if got, err := os.ReadFile(certPath); err != nil || string(got) != km.oidevidCertPEM {
		t.Errorf("oIDevID cert: got %q, %v; want the rotated cert", got, err)
	}
	if target, err := os.Readlink(cfg.SrvCertLnk); err != nil || target != certPath {
		t.Errorf("server cert link: got %q, %v; want %q", target, err, certPath)
	}
	if linkExists(cfg.SrvKeyLnk) {
		t.Error("server key link should not exist for a TPM-backed certificate")
	}
	if got, err := os.ReadFile(cfg.OIakCertFile); err != nil || string(got) != km.oiakCertPEM {
		t.Errorf("oIAK cert: got %q, %v; want the rotated cert", got, err)
	}
}

func TestEnrollzRotateOIakCert_OidevidWrongProfile(t *testing.T) {
	km := newTestTpmKeyMaterial(t)
	cfg := newTestTPMServingConfig(t, km)
	srv := newTestEnrollzServer(t, cfg)

	req := &enrollz_pb.RotateOIakCertRequest{
		SslProfileId: "some-profile",
		Updates: []*enrollz_pb.ControlCardCertUpdate{{
			ControlCardSelection: testCardSelection(),
			OiakCert:             km.oiakCertPEM,
			OidevidCert:          km.oidevidCertPEM,
		}},
	}
	_, err := srv.RotateOIakCert(context.Background(), req)
	testErr(err, codes.InvalidArgument, "oIDevID can only be installed in the", t)
}

func TestEnrollzRotateOIakCert_OidevidKeyMismatch(t *testing.T) {
	km := newTestTpmKeyMaterial(t)
	cfg := newTestTPMServingConfig(t, km)
	srv := newTestEnrollzServer(t, cfg)

	wrongKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate wrong key: %v", err)
	}
	req := &enrollz_pb.RotateOIakCertRequest{
		SslProfileId: defaultProfile,
		Updates: []*enrollz_pb.ControlCardCertUpdate{{
			ControlCardSelection: testCardSelection(),
			OiakCert:             km.oiakCertPEM,
			OidevidCert:          selfSignedCertPEM(t, wrongKey),
		}},
	}
	_, err = srv.RotateOIakCert(context.Background(), req)
	testErr(err, codes.InvalidArgument, "leaf cert public key does not match IDevID public key", t)
	if target, _ := os.Readlink(cfg.SrvCertLnk); target != cfg.IDevIDCertFile {
		t.Errorf("server cert link changed on a rejected request: %q", target)
	}
	if _, err := os.Stat(cfg.OIakCertFile); !os.IsNotExist(err) {
		t.Error("oIAK cert should not be written when the request is rejected")
	}
}

// ---- RotateOIakCert cert chain validation tests -----------------------------

func TestEnrollzRotateOIakCert_OiakInvalidCert(t *testing.T) {
	km := newTestTpmKeyMaterial(t)
	cfg := newTestConfig(t)
	srv := newTestEnrollzServer(t, cfg)
	writeKeyMaterial(t, cfg.IakCertFile, cfg.IDevIDCertFile, km)

	req := &enrollz_pb.RotateOIakCertRequest{
		Updates: []*enrollz_pb.ControlCardCertUpdate{{
			ControlCardSelection: testCardSelection(),
			OiakCert:             "-----BEGIN CERTIFICATE-----\nbm90YWNlcnQ=\n-----END CERTIFICATE-----\n",
		}},
	}
	_, err := srv.RotateOIakCert(context.Background(), req)
	testErr(err, codes.InvalidArgument, "cert chain contains invalid X.509 certificate", t)
}

func TestEnrollzRotateOIakCert_OiakInvalidInterCert(t *testing.T) {
	km := newTestTpmKeyMaterial(t)
	cfg := newTestConfig(t)
	srv := newTestEnrollzServer(t, cfg)
	writeKeyMaterial(t, cfg.IakCertFile, cfg.IDevIDCertFile, km)

	// Build a chain where the leaf has the correct IAK public key but is followed
	// by an unrelated root that did not sign it, breaking the chain of trust.
	unrelatedKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate unrelated key: %v", err)
	}
	brokenChain := km.oiakCertPEM + selfSignedCertPEM(t, unrelatedKey)

	req := &enrollz_pb.RotateOIakCertRequest{
		Updates: []*enrollz_pb.ControlCardCertUpdate{{
			ControlCardSelection: testCardSelection(),
			OiakCert:             brokenChain,
		}},
	}
	_, err = srv.RotateOIakCert(context.Background(), req)
	testErr(err, codes.InvalidArgument, "failed to validate oIAK cert with: cert chain verification failed", t)
}

func TestEnrollzRotateOIakCert_OiakKeyMismatch(t *testing.T) {
	km := newTestTpmKeyMaterial(t)
	cfg := newTestConfig(t)
	srv := newTestEnrollzServer(t, cfg)
	writeKeyMaterial(t, cfg.IakCertFile, cfg.IDevIDCertFile, km)

	wrongKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate wrong key: %v", err)
	}
	req := &enrollz_pb.RotateOIakCertRequest{
		Updates: []*enrollz_pb.ControlCardCertUpdate{{
			ControlCardSelection: testCardSelection(),
			OiakCert:             selfSignedCertPEM(t, wrongKey),
		}},
	}
	_, err = srv.RotateOIakCert(context.Background(), req)
	testErr(err, codes.InvalidArgument, "leaf cert public key does not match IAK public key", t)
}

// ---- RotateOIakCert I/O success and rollback tests --------------------------

func TestEnrollzRotateOIakCert_Success(t *testing.T) {
	km := newTestTpmKeyMaterial(t)
	cfg := newTestConfig(t)
	srv := newTestEnrollzServer(t, cfg)
	writeKeyMaterial(t, cfg.IakCertFile, cfg.IDevIDCertFile, km)
	if err := os.WriteFile(cfg.OIakCertFile, []byte("prior-oiak-cert-content"), 0644); err != nil {
		t.Fatalf("setup: write prior oIAK cert: %v", err)
	}

	req := &enrollz_pb.RotateOIakCertRequest{
		Updates: []*enrollz_pb.ControlCardCertUpdate{{
			ControlCardSelection: testCardSelection(),
			OiakCert:             km.oiakCertPEM,
		}},
	}
	if _, err := srv.RotateOIakCert(context.Background(), req); err != nil {
		t.Fatalf("RotateOIakCert returned unexpected error: %v", err)
	}

	got, err := os.ReadFile(cfg.OIakCertFile)
	if err != nil {
		t.Fatalf("oIAK cert not written: %v", err)
	}
	if string(got) != km.oiakCertPEM {
		t.Errorf("oIAK cert content: got %q, want %q", got, km.oiakCertPEM)
	}
	if _, err := os.Stat(cfg.OIakCertFile + backupExt); !os.IsNotExist(err) {
		t.Error("oIAK backup file should be cleaned up after successful rotation")
	}
}

func TestEnrollzRotateOIakCert_WriteFailureRollsBack(t *testing.T) {
	km := newTestTpmKeyMaterial(t)
	cfg := newTestConfig(t)
	srv := newTestEnrollzServer(t, cfg)
	writeKeyMaterial(t, cfg.IakCertFile, cfg.IDevIDCertFile, km)

	const priorContent = "prior-oiak-cert-content"
	if err := os.WriteFile(cfg.OIakCertFile, []byte(priorContent), 0644); err != nil {
		t.Fatalf("setup: write prior oIAK cert: %v", err)
	}

	// Fail only the rotation write. The rollback that follows writes to the same
	// path, so it must be allowed through for the restore to be observable.
	rotationFailed := false
	patchWrite := gomonkey.ApplyFunc(attemptWrite, func(name string, data []byte, perm os.FileMode) error {
		if name == cfg.OIakCertFile && !rotationFailed {
			rotationFailed = true
			return fmt.Errorf("permission denied")
		}
		return os.WriteFile(name, data, perm)
	})
	defer patchWrite.Reset()

	req := &enrollz_pb.RotateOIakCertRequest{
		Updates: []*enrollz_pb.ControlCardCertUpdate{{
			ControlCardSelection: testCardSelection(),
			OiakCert:             km.oiakCertPEM,
		}},
	}
	_, err := srv.RotateOIakCert(context.Background(), req)
	testErr(err, codes.Internal, fmt.Sprintf("failed to write oIAK cert to %s: permission denied", cfg.OIakCertFile), t)

	got, err := os.ReadFile(cfg.OIakCertFile)
	if err != nil {
		t.Fatalf("read oIAK cert after rollback: %v", err)
	}
	if string(got) != priorContent {
		t.Errorf("oIAK cert after rollback: got %q, want the prior content %q", got, priorContent)
	}
	if _, err := os.Stat(cfg.OIakCertFile + backupExt); !os.IsNotExist(err) {
		t.Error("oIAK backup file should be cleaned up after rollback")
	}
}

// ---- certFileBackup unit tests ----------------------------------------------

func TestEnrollzCertFileBackup_NewFilePresent(t *testing.T) {
	origPath := filepath.Join(t.TempDir(), "cert.pem")
	origContent := []byte("original cert content")
	if err := os.WriteFile(origPath, origContent, 0644); err != nil {
		t.Fatalf("setup: %v", err)
	}
	// Ensure exact permissions regardless of umask.
	if err := os.Chmod(origPath, 0644); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	b, err := newCertFileBackup(origPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !b.backupNeeded {
		t.Error("backupNeeded should be true when file exists")
	}
	if b.origPerm != 0644 {
		t.Errorf("origPerm: got %v, want 0644", b.origPerm)
	}
	backupContent, err := os.ReadFile(b.backupPath)
	if err != nil {
		t.Fatalf("backup file not created: %v", err)
	}
	if !bytes.Equal(backupContent, origContent) {
		t.Errorf("backup content: got %q, want %q", backupContent, origContent)
	}
}

func TestEnrollzCertFileBackup_RestoreWhenBackupNeeded(t *testing.T) {
	origPath := filepath.Join(t.TempDir(), "cert.pem")
	origContent := []byte("original content")
	if err := os.WriteFile(origPath, origContent, 0644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	b, err := newCertFileBackup(origPath)
	if err != nil {
		t.Fatalf("newCertFileBackup: %v", err)
	}
	if err := os.WriteFile(origPath, []byte("new content"), 0644); err != nil {
		t.Fatalf("overwrite: %v", err)
	}

	if err := b.restore(); err != nil {
		t.Fatalf("restore: %v", err)
	}
	got, err := os.ReadFile(origPath)
	if err != nil {
		t.Fatalf("read after restore: %v", err)
	}
	if !bytes.Equal(got, origContent) {
		t.Errorf("content after restore: got %q, want %q", got, origContent)
	}
	// restore calls cleanup, so the backup file should also be gone.
	if _, err := os.Stat(b.backupPath); !os.IsNotExist(err) {
		t.Error("backup file should be removed after restore")
	}
}

func TestEnrollzCertFileBackup_RestoreWhenNoBackupFileExisted(t *testing.T) {
	origPath := filepath.Join(t.TempDir(), "cert.pem")

	// File absent at backup time.
	b, err := newCertFileBackup(origPath)
	if err != nil {
		t.Fatalf("newCertFileBackup: %v", err)
	}
	if _, err := os.Stat(b.backupPath); !os.IsNotExist(err) {
		t.Error("no backup file should be created when original is absent")
	}
	// File written after backup - simulates a new cert that needs rolling back.
	if err := os.WriteFile(origPath, []byte("new content"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := b.restore(); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if _, err := os.Stat(origPath); !os.IsNotExist(err) {
		t.Error("file should be removed when rolling back a file that had no prior backup")
	}
}

func TestEnrollzCertFileBackup_RestoreNoopWhenNoBackupAndFileAbsent(t *testing.T) {
	origPath := filepath.Join(t.TempDir(), "cert.pem")
	b, err := newCertFileBackup(origPath)
	if err != nil {
		t.Fatalf("newCertFileBackup: %v", err)
	}
	if err := b.restore(); err != nil {
		t.Fatalf("restore: unexpected error: %v", err)
	}
}

func TestEnrollzCertFileBackup_CleanupRemovesBackupFile(t *testing.T) {
	origPath := filepath.Join(t.TempDir(), "cert.pem")
	if err := os.WriteFile(origPath, []byte("content"), 0644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	b, err := newCertFileBackup(origPath)
	if err != nil {
		t.Fatalf("newCertFileBackup: %v", err)
	}

	b.cleanup()

	if _, err := os.Stat(b.backupPath); !os.IsNotExist(err) {
		t.Error("backup file should be removed after cleanup")
	}
	if _, err := os.Stat(origPath); err != nil {
		t.Errorf("original file should be untouched after cleanup: %v", err)
	}
}
