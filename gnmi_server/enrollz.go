package gnmi

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	log "github.com/golang/glog"
	enrollz_pb "github.com/openconfig/attestz/proto/tpm_enrollz"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// certFileBackup backs up a cert file to the filesystem before modification,
// enabling rollback to the previous state if the enclosing operation fails.
type certFileBackup struct {
	origPath     string
	backupPath   string
	backupNeeded bool
	origPerm     os.FileMode
}

func newCertFileBackup(origPath string) (*certFileBackup, error) {
	b := &certFileBackup{origPath: origPath, backupPath: origPath + backupExt}
	info, err := os.Stat(origPath)
	if os.IsNotExist(err) {
		return b, nil
	} else if err != nil {
		return nil, err
	}
	b.backupNeeded = true
	b.origPerm = info.Mode().Perm()

	if e := copyFile(origPath, b.backupPath); e != nil {
		return nil, status.Errorf(codes.Internal,
			"failed to create backup file for %s: %v", origPath, e)
	}
	return b, nil
}

// restore reverts origPath from the backup file, then removes the backup.
// If no file existed before the backup was taken, the file at origPath is removed.
func (b *certFileBackup) restore() error {
	if b.backupNeeded {
		data, err := os.ReadFile(b.backupPath)
		if err != nil {
			return status.Errorf(codes.Internal,
				"certFileBackup: failed to read backup %s: %v", b.backupPath, err)
		} else if err := attemptWrite(b.origPath, data, b.origPerm); err != nil {
			return status.Errorf(codes.Internal,
				"certFileBackup: failed to restore %s from backup: %v", b.origPath, err)
		}
	} else if err := os.Remove(b.origPath); err != nil && !os.IsNotExist(err) {
		return status.Errorf(codes.Internal,
			"certFileBackup: failed to remove %s during rollback: %v", b.origPath, err)
	}
	b.cleanup()
	return nil
}

// cleanup removes the backup file. Call on success to leave no backup artifacts.
func (b *certFileBackup) cleanup() {
	if !b.backupNeeded {
		return
	}
	if err := os.Remove(b.backupPath); err != nil && !os.IsNotExist(err) {
		log.Errorf("certFileBackup: failed to remove backup %s: %v", b.backupPath, err)
	}
}

type TpmEnrollzServer struct {
	*Server
	enrollz_pb.UnimplementedTpmEnrollzServiceServer
}

func NewTpmEnrollzServer(srv *Server) *TpmEnrollzServer {
	return &TpmEnrollzServer{Server: srv}
}

func (srv *TpmEnrollzServer) GetIakCert(ctx context.Context, req *enrollz_pb.GetIakCertRequest) (*enrollz_pb.GetIakCertResponse, error) {
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
	controlCardId, err := makeControlCardVendorId(card)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to build control card vendor ID: %v", err)
	}
	log.V(1).Infof("Using ControlCardId: %v", controlCardId)

	iakCertBytes, err := os.ReadFile(srv.config.IakCertFile)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to read IAK cert from %s: %v", srv.config.IakCertFile, err)
	}

	idevidCertBytes, err := os.ReadFile(srv.config.IDevIDCertFile)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to read IDevID cert from %s: %v", srv.config.IDevIDCertFile, err)
	}

	return &enrollz_pb.GetIakCertResponse{
		ControlCardId: controlCardId,
		IakCert:       string(iakCertBytes),
		IdevidCert:    string(idevidCertBytes),
	}, nil
}

func (srv *TpmEnrollzServer) RotateOIakCert(ctx context.Context, req *enrollz_pb.RotateOIakCertRequest) (*enrollz_pb.RotateOIakCertResponse, error) {
	if !certzMu.TryLock() {
		return nil, status.Errorf(codes.Aborted,
			"concurrent certificate RPC is in progress")
	}
	defer certzMu.Unlock()

	if len(req.GetUpdates()) != 1 {
		return nil, status.Errorf(codes.InvalidArgument, "exactly one update must be provided, got %d", len(req.GetUpdates()))
	}
	update := req.GetUpdates()[0]

	cards, err := srv.Server.controlCards()
	if err != nil {
		return nil, err
	}
	if _, err := resolveControlCard(update.GetControlCardSelection(), cards); err != nil {
		return nil, err
	}

	if update.GetOiakCert() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "oiak_cert must be provided")
	}

	hasOidevid := update.GetOidevidCert() != ""
	hasSslProfile := req.GetSslProfileId() != ""
	if hasOidevid && !hasSslProfile {
		return nil, status.Errorf(codes.InvalidArgument, "ssl_profile_id must be provided when oidevid_cert is present")
	}
	if !hasOidevid && hasSslProfile {
		return nil, status.Errorf(codes.InvalidArgument, "ssl_profile_id must not be provided without oidevid_cert")
	}

	if hasOidevid {
		// Installing an oIDevID as the gNxI server certificate only works if the
		// TLS stack can sign with the TPM-resident IDevID private key, since the
		// rotation leaves no private key file behind. This build serves TLS from
		// a cert/key pair on disk, so the oIAK-only rotation is the supported
		// flow until a TPM signer is wired into SrvAdvConfig.
		return nil, status.Error(codes.Unimplemented,
			"oIDevID rotation requires a TPM-backed TLS signer, which this build does not provide; "+
				"send the update without oidevid_cert and ssl_profile_id to rotate the oIAK cert only")
	}

	iakPubKey, err := readPublicKeyFromCertFile(srv.config.IakCertFile)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to read IAK public key from %s: %v",
			srv.config.IakCertFile, err)
	}
	if err := validateRotatedCertChain(update.GetOiakCert(), iakPubKey, "IAK public key"); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to validate oIAK cert with: %v", err)
	}

	oiakBackup, err := newCertFileBackup(srv.config.OIakCertFile)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to back up oIAK cert: %v", err)
	}

	committed := false
	defer func() {
		if !committed {
			if restoreErr := oiakBackup.restore(); restoreErr != nil {
				log.Errorf("failed to restore oIAK cert backup with: %v", restoreErr)
			}
		} else {
			oiakBackup.cleanup()
		}
	}()

	if err := attemptWrite(srv.config.OIakCertFile, []byte(update.GetOiakCert()), 0644); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to write oIAK cert to %s: %v",
			srv.config.OIakCertFile, err)
	}

	committed = true
	return &enrollz_pb.RotateOIakCertResponse{}, nil
}

// readPublicKeyFromCertFile reads the first PEM certificate from path and returns its public key.
func readPublicKeyFromCertFile(path string) (crypto.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, status.Errorf(codes.Internal, "no certificate PEM block found in %s", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert.PublicKey, nil
}

// pubKeyComparable is satisfied by crypto public key types that support
// structural equality via their Equal method.
type pubKeyComparable interface {
	Equal(x crypto.PublicKey) bool
}

// validateRotatedCertChain parses the chain and verifies all PEM blocks
// are valid x509 certificates and the chain of trust is valid. It also
// verifies that the leaf cert contains the specified public key.
func validateRotatedCertChain(chain string, expectedLeafKey crypto.PublicKey, keyDesc string) error {
	var certs []*x509.Certificate
	rest := []byte(chain)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return fmt.Errorf("cert chain contains non-certificate PEM block of type %q", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("cert chain contains invalid X.509 certificate: %v", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return fmt.Errorf("failed to parse certs in cert chain")
	}

	// verify leaf cert public key
	comparableKey, ok := expectedLeafKey.(pubKeyComparable)
	if !ok {
		return fmt.Errorf("expected leaf key type %T does not support equality comparison", expectedLeafKey)
	}
	if !comparableKey.Equal(certs[0].PublicKey) {
		return fmt.Errorf("leaf cert public key does not match %s", keyDesc)
	}

	// verify chain of trust if there are any intermediate certs
	if len(certs) > 1 {
		roots := x509.NewCertPool()
		roots.AddCert(certs[len(certs)-1])
		intermediates := x509.NewCertPool()
		for i := 1; i < len(certs)-1; i++ {
			intermediates.AddCert(certs[i])
		}
		if _, err := certs[0].Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}); err != nil {
			return fmt.Errorf("cert chain verification failed: %v", err)
		}
	}
	return nil
}
