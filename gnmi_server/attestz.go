package gnmi

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"

	log "github.com/golang/glog"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	common_pb "github.com/openconfig/attestz/proto/common_definitions"
	attestz_pb "github.com/openconfig/attestz/proto/tpm_attestz"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Default location of the saved TPM context for the IAK signing key,
// used when --iak_context_file is not given.
const defaultIakContextPath = "/run/tpm/iak_context.bin"

type TpmAttestzServer struct {
	*Server
	attestz_pb.UnimplementedTpmAttestzServiceServer
}

func NewTpmAttestzServer(srv *Server) *TpmAttestzServer {
	return &TpmAttestzServer{Server: srv}
}

func (srv *TpmAttestzServer) Attest(ctx context.Context, req *attestz_pb.AttestRequest) (*attestz_pb.AttestResponse, error) {
	if !certzMu.TryLock() {
		return nil, status.Errorf(codes.Aborted,
			"concurrent certificate RPC is in progress")
	}
	defer certzMu.Unlock()

	cards, err := srv.Server.controlCards()
	if err != nil {
		return nil, err
	}
	card, err := resolveControlCard(req.GetControlCardSelection(), cards)
	if err != nil {
		return nil, err
	}

	cfg := srv.Server.config
	if cfg.TPMPath == "" {
		return nil, status.Error(codes.FailedPrecondition, "TPM path not configured")
	}
	if len(req.GetPcrIndices()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "pcr_indices must not be empty")
	}

	seen := make(map[int32]struct{}, len(req.GetPcrIndices()))
	for _, ind := range req.GetPcrIndices() {
		if _, ok := seen[ind]; ok {
			return nil, status.Errorf(codes.InvalidArgument, "duplicate PCR index in request: %d", ind)
		}
		seen[ind] = struct{}{}
	}

	hashAlg, err := tpm20HashToAlgID(req.GetHashAlgo())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	oiakCertBytes, err := os.ReadFile(cfg.OIakCertFile)
	if errors.Is(err, os.ErrNotExist) {
		// The oIAK cert is installed by enrollz RotateOIakCert, so a device
		// that has not been enrolled yet cannot be attested.
		return nil, status.Errorf(codes.FailedPrecondition,
			"no oIAK cert at %s; the device must be enrolled before it can be attested", cfg.OIakCertFile)
	} else if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to read oIAK cert from %s: %v", cfg.OIakCertFile, err)
	}

	tpmDev, err := linuxtpm.Open(cfg.TPMPath)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to open TPM at %s: %v", cfg.TPMPath, err)
	}
	defer tpmDev.Close()

	iakHandle := tpm2.TPMIDHContext(cfg.IakHandle)
	if iakHandle == 0 {
		iakContextFile := cfg.IakContextFile
		if iakContextFile == "" {
			iakContextFile = defaultIakContextPath
		}
		iakHandle, err = loadTPMContext(tpmDev, iakContextFile)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "load IAK context: %v", err)
		}
		defer func() {
			if _, err := (tpm2.FlushContext{FlushHandle: iakHandle}).Execute(tpmDev); err != nil {
				log.Errorf("failed to flush IAK TPM context: %v", err)
			}
		}()
	}

	pcrValues, err := readSelectPCRValues(tpmDev, hashAlg, req.GetPcrIndices())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read PCR values: %v", err)
	}

	quoteRsp, err := tpm2.Quote{
		SignHandle: tpm2.NamedHandle{
			Handle: tpm2.TPMHandle(iakHandle),
			Name:   tpm2.TPM2BName{},
		},
		QualifyingData: tpm2.TPM2BData{Buffer: req.GetNonce()},
		// always defer to signing key's SigScheme
		InScheme:  tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgNull},
		PCRSelect: buildPCRSelection(hashAlg, req.GetPcrIndices()),
	}.Execute(tpmDev)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "TPM Quote: %v", err)
	}

	controlCardId, err := makeControlCardVendorId(card)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to read ControlCardId: %v", err)
	}

	return &attestz_pb.AttestResponse{
		AttestationCert: &attestz_pb.AttestResponse_AttestationCert{
			Value: &attestz_pb.AttestResponse_AttestationCert_OiakCert{
				OiakCert: string(oiakCertBytes),
			},
		},
		ControlCardId:  controlCardId,
		PcrValues:      pcrValues,
		Quoted:         tpm2.Marshal(quoteRsp.Quoted),
		QuoteSignature: tpm2.Marshal(quoteRsp.Signature),
	}, nil
}

// tpm20HashToAlgID maps the proto hash enum to the go-tpm algorithm ID.
// Only SHA256 is currently supported.
func tpm20HashToAlgID(h common_pb.Tpm20HashAlgo) (tpm2.TPMAlgID, error) {
	switch h {
	case common_pb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA256:
		return tpm2.TPMAlgSHA256, nil
	default:
		return 0, fmt.Errorf("unsupported hash algorithm: %v, only SHA256 is supported", h)
	}
}

// loadTPMContext reads a saved TPM context from the file system and loads it into the TPM,
// returning the transient handle assigned by the TPM.
func loadTPMContext(t transport.TPM, path string) (tpm2.TPMIDHContext, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("failed to read context file %s: %w", path, err)
	}
	ctx, err := tpm2.Unmarshal[tpm2.TPMSContext](b)
	if err != nil {
		return 0, fmt.Errorf("failed to unmarshal TPM context: %w", err)
	}
	rsp, err := tpm2.ContextLoad{Context: *ctx}.Execute(t)
	if err != nil {
		return 0, fmt.Errorf("TPM2_ContextLoad failed with: %w", err)
	}
	return rsp.LoadedHandle, nil
}

// buildPCRSelection builds a TPMLPCRSelection for the given hash algorithm and indices.
func buildPCRSelection(hashAlg tpm2.TPMAlgID, indices []int32) tpm2.TPMLPCRSelection {
	uindices := make([]uint, 0, len(indices))
	for _, idx := range indices {
		uindices = append(uindices, uint(idx))
	}
	return tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{{
			Hash:      hashAlg,
			PCRSelect: tpm2.PCClientCompatible.PCRs(uindices...),
		}},
	}
}

// readSelectPCRValues reads PCR values for the requested indices, looping until all
// are consumed. TPM2_PCR_Read returns at most 8 digests per call (TPML_DIGEST
// max count), so multiple calls to tpm2.PCRRead are required for larger selections.
func readSelectPCRValues(t transport.TPM, hashAlg tpm2.TPMAlgID, indices []int32) (map[int32][]byte, error) {
	sorted := make([]int32, len(indices))
	copy(sorted, indices)
	slices.Sort(sorted)

	result := make(map[int32][]byte, len(sorted))
	numRead := 0

	for numRead != len(sorted) {
		rsp, err := tpm2.PCRRead{
			PCRSelectionIn: buildPCRSelection(hashAlg, sorted[numRead:]),
		}.Execute(t)
		if err != nil {
			return nil, err
		}
		if len(rsp.PCRValues.Digests) == 0 {
			return nil, fmt.Errorf("empty digest returned by PCRRead; %d/%d PCRs read", numRead, len(sorted))
		}

		// the TPM returns digests in ascending PCR index order,
		// so sorted[numRead+i] corresponds to Digests[i].
		for i, digest := range rsp.PCRValues.Digests {
			result[sorted[numRead+i]] = digest.Buffer
		}
		numRead += len(rsp.PCRValues.Digests)
	}
	return result, nil
}
