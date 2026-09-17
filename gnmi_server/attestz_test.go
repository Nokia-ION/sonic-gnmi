package gnmi

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	common_pb "github.com/openconfig/attestz/proto/common_definitions"
	attestz_pb "github.com/openconfig/attestz/proto/tpm_attestz"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
)

// mockTpmCloser satisfies transport.TPMCloser for tests that mock TPM interactions.
type mockTpmCloser struct{}

func (f *mockTpmCloser) Send(_ []byte) ([]byte, error) { return nil, nil }
func (f *mockTpmCloser) Close() error                  { return nil }

// newTestTpmAttestzServer constructs an attestz server with pre-populated
// hardware identity and the given config.
func newTestTpmAttestzServer(t *testing.T, cfg *Config) *TpmAttestzServer {
	t.Helper()
	return NewTpmAttestzServer(&Server{
		cachedControlCards: testControlCards(),
		config:             cfg,
	})
}

// patchTPMForAttest applies gomonkey patches for TPM interactions
// in Attest that are not under test: opening the device, loading the IAK
// context, and flushing it on exit. PCRRead and Quote are left un-patched so
// callers can control their return values.
func patchTPMForAttest(t *testing.T) func() {
	t.Helper()

	patchOpen := gomonkey.ApplyFunc(linuxtpm.Open, func(_ string) (transport.TPMCloser, error) {
		return &mockTpmCloser{}, nil
	})
	patchLoadCtx := gomonkey.ApplyFunc(loadTPMContext, func(_ transport.TPM, _ string) (tpm2.TPMIDHContext, error) {
		return 0, nil
	})
	patchFlush := gomonkey.ApplyMethod(reflect.TypeOf(tpm2.FlushContext{}), "Execute",
		func(_ tpm2.FlushContext, _ transport.TPM, _ ...tpm2.Session) (*tpm2.FlushContextResponse, error) {
			return &tpm2.FlushContextResponse{}, nil
		})

	return func() {
		patchOpen.Reset()
		patchLoadCtx.Reset()
		patchFlush.Reset()
	}
}

// ---- Attest input validation tests ------------------------------------------

func TestAttest_NoSelection(t *testing.T) {
	srv := newTestTpmAttestzServer(t, newTestConfig(t))
	_, err := srv.Attest(context.Background(), &attestz_pb.AttestRequest{})
	testErr(err, codes.InvalidArgument, "control_card_selection must be specified", t)
}

func TestAttest_WrongSelection(t *testing.T) {
	srv := newTestTpmAttestzServer(t, newTestConfig(t))
	req := &attestz_pb.AttestRequest{
		ControlCardSelection: &common_pb.ControlCardSelection{
			ControlCardId: &common_pb.ControlCardSelection_Serial{Serial: "WRONG-SERIAL"},
		},
	}
	_, err := srv.Attest(context.Background(), req)
	testErr(err, codes.InvalidArgument, "no control card matches selection", t)
}

func TestAttest_TPMPathNotConfigured(t *testing.T) {
	srv := newTestTpmAttestzServer(t, &Config{})
	_, err := srv.Attest(context.Background(), &attestz_pb.AttestRequest{
		ControlCardSelection: testCardSelection(),
	})
	testErr(err, codes.FailedPrecondition, "TPM path not configured", t)
}

func TestAttest_EmptyPcrIndices(t *testing.T) {
	srv := newTestTpmAttestzServer(t, newTestConfig(t))
	req := &attestz_pb.AttestRequest{
		ControlCardSelection: testCardSelection(),
	}
	_, err := srv.Attest(context.Background(), req)
	testErr(err, codes.InvalidArgument, "pcr_indices must not be empty", t)
}

func TestAttest_DuplicatePcrIndex(t *testing.T) {
	srv := newTestTpmAttestzServer(t, newTestConfig(t))
	req := &attestz_pb.AttestRequest{
		ControlCardSelection: testCardSelection(),
		PcrIndices:           []int32{0, 1, 0},
	}
	_, err := srv.Attest(context.Background(), req)
	testErr(err, codes.InvalidArgument, "duplicate PCR index in request: 0", t)
}

func TestAttest_UnsupportedHashAlgo(t *testing.T) {
	srv := newTestTpmAttestzServer(t, newTestConfig(t))
	req := &attestz_pb.AttestRequest{
		ControlCardSelection: testCardSelection(),
		PcrIndices:           []int32{0},
		HashAlgo:             common_pb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA512,
	}
	_, err := srv.Attest(context.Background(), req)
	testErr(err, codes.InvalidArgument, "unsupported hash algorithm", t)
}

func TestAttest_MissingOiakCert(t *testing.T) {
	// The oIAK cert path points into a temp dir; the file is intentionally absent,
	// which is the state of a device that has not been enrolled yet.
	cfg := newTestConfig(t)
	srv := newTestTpmAttestzServer(t, cfg)
	req := &attestz_pb.AttestRequest{
		ControlCardSelection: testCardSelection(),
		PcrIndices:           []int32{0},
		HashAlgo:             common_pb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA256,
	}
	_, err := srv.Attest(context.Background(), req)
	testErr(err, codes.FailedPrecondition, fmt.Sprintf("no oIAK cert at %s", cfg.OIakCertFile), t)
}

// ---- Attest success test ----------------------------------------------------

func TestAttest_Success(t *testing.T) {
	const oiakContent = "OIAK_CERT_PEM"
	cfg := newTestConfig(t)
	srv := newTestTpmAttestzServer(t, cfg)
	if err := os.WriteFile(cfg.OIakCertFile, []byte(oiakContent), 0644); err != nil {
		t.Fatalf("setup: write oIAK cert: %v", err)
	}

	resetTPMPatch := patchTPMForAttest(t)
	defer resetTPMPatch()

	mockQuoted := tpm2.BytesAs2B[tpm2.TPMSAttest, *tpm2.TPMSAttest]([]byte("mock-quoted-data"))
	mockSig := tpm2.TPMTSignature{SigAlg: tpm2.TPMAlgNull}
	patchQuote := gomonkey.ApplyMethod(reflect.TypeOf(tpm2.Quote{}), "Execute",
		func(_ tpm2.Quote, _ transport.TPM, _ ...tpm2.Session) (*tpm2.QuoteResponse, error) {
			return &tpm2.QuoteResponse{Quoted: mockQuoted, Signature: mockSig}, nil
		})
	defer patchQuote.Reset()

	patchPCRRead := gomonkey.ApplyMethod(reflect.TypeOf(tpm2.PCRRead{}), "Execute",
		func(_ tpm2.PCRRead, _ transport.TPM, _ ...tpm2.Session) (*tpm2.PCRReadResponse, error) {
			return &tpm2.PCRReadResponse{
				PCRValues: tpm2.TPMLDigest{
					Digests: []tpm2.TPM2BDigest{
						{Buffer: []byte{0xaa}},
						{Buffer: []byte{0xbb}},
						{Buffer: []byte{0xcc}},
					},
				},
			}, nil
		})
	defer patchPCRRead.Reset()

	req := &attestz_pb.AttestRequest{
		ControlCardSelection: testCardSelection(),
		PcrIndices:           []int32{7, 0, 3}, // unsorted - exercises sort in readSelectPCRValues
		HashAlgo:             common_pb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA256,
		Nonce:                []byte("test-nonce"),
	}
	resp, err := srv.Attest(context.Background(), req)
	if err != nil {
		t.Fatalf("Attest returned unexpected error: %v", err)
	}

	want := &attestz_pb.AttestResponse{
		AttestationCert: &attestz_pb.AttestResponse_AttestationCert{
			Value: &attestz_pb.AttestResponse_AttestationCert_OiakCert{
				OiakCert: oiakContent,
			},
		},
		ControlCardId: &common_pb.ControlCardVendorId{
			ControlCardRole:     common_pb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE,
			ControlCardSerial:   testControlCardSerial,
			ControlCardSlot:     testControlCardSlot,
			ChassisManufacturer: testChassisManufacturer,
			ChassisPartNumber:   testChassisPartNumber,
			ChassisSerialNumber: testChassisSerialNumber,
		},
		PcrValues: map[int32][]byte{
			0: {0xaa},
			3: {0xbb},
			7: {0xcc},
		},
		Quoted:         tpm2.Marshal(mockQuoted),
		QuoteSignature: tpm2.Marshal(mockSig),
	}
	if !proto.Equal(resp, want) {
		t.Errorf("Attest response mismatch:\ngot: %v\nwant: %v", resp, want)
	}
}
