package gnmi

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	log "github.com/golang/glog"
	enrollz_pb "github.com/openconfig/attestz/proto/tpm_enrollz"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	// oIDevIDCertName is written next to the default profile's links. The
	// _cert.pem suffix makes a restart keep it as an active rotation.
	oIDevIDCertName = "oIDevID_cert.pem"
	oIDevIDVersion  = "oIDevID"
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

	iakCertBytes, err := readIdentityCert(srv.config, srv.config.IakCertFile, srv.config.IakCertNVIndex)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to read IAK cert from %s: %v", srv.config.IakCertFile, err)
	}

	idevidCertBytes, err := readIdentityCert(srv.config, srv.config.IDevIDCertFile, srv.config.IDevIDCertNVIndex)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to read IDevID cert from %s: %v", srv.config.IDevIDCertFile, err)
	}

	return &enrollz_pb.GetIakCertResponse{
		ControlCardId: controlCardId,
		IakCert:       string(iakCertBytes),
		IdevidCert:    string(idevidCertBytes),
		// RotateOIakCert takes the updates list, not the deprecated
		// per-card fields that owners send without this flag.
		AtomicCertRotationSupported: true,
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
		// The rotation leaves no private key file behind, so the listener
		// must be able to sign with the TPM-resident IDevID key.
		if !tpmTLSEnabled(srv.config) {
			return nil, status.Error(codes.Unimplemented,
				"oIDevID rotation requires a TPM-backed TLS signer, which is not configured (--tpm_key_handle); "+
					"send the update without oidevid_cert and ssl_profile_id to rotate the oIAK cert only")
		}
		if req.GetSslProfileId() != defaultProfile {
			return nil, status.Errorf(codes.InvalidArgument,
				"oIDevID can only be installed in the %q SSL profile, got %q", defaultProfile, req.GetSslProfileId())
		}
	}

	iakPubKey, err := readIdentityPublicKey(srv.config, srv.config.IakCertFile, srv.config.IakCertNVIndex)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to read IAK public key from %s: %v",
			srv.config.IakCertFile, err)
	}
	if err := validateRotatedCertChain(update.GetOiakCert(), iakPubKey, "IAK public key"); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to validate oIAK cert with: %v", err)
	}
	if hasOidevid {
		idevidPubKey, err := readIdentityPublicKey(srv.config, srv.config.IDevIDCertFile, srv.config.IDevIDCertNVIndex)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to read IDevID public key from %s: %v",
				srv.config.IDevIDCertFile, err)
		}
		if err := validateRotatedCertChain(update.GetOidevidCert(), idevidPubKey, "IDevID public key"); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "failed to validate oIDevID cert with: %v", err)
		}
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
	if hasOidevid {
		if err := srv.rotateOIDevIDCert(update.GetOidevidCert()); err != nil {
			return nil, err
		}
	}

	committed = true
	return &enrollz_pb.RotateOIakCertResponse{}, nil
}

// rotateOIDevIDCert installs oidevid as the default profile's server
// certificate, served with the TPM-resident IDevID key. On failure the
// previous certificate and links are restored.
// NOTE: certzMu has to be locked when entering this function.
func (srv *TpmEnrollzServer) rotateOIDevIDCert(oidevid string) error {
	cfg := srv.config
	certPath := filepath.Join(filepath.Dir(cfg.SrvCertLnk), oIDevIDCertName)
	backup, err := newCertFileBackup(certPath)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to back up oIDevID cert: %v", err)
	}

	muPath.Lock()
	defer muPath.Unlock()
	oldCert, _ := os.Readlink(cfg.SrvCertLnk)
	oldKey, _ := os.Readlink(cfg.SrvKeyLnk)
	committed := false
	defer func() {
		if committed {
			backup.cleanup()
			return
		}
		if err := backup.restore(); err != nil {
			log.Errorf("failed to restore oIDevID cert backup with: %v", err)
		}
		for link, target := range map[string]string{cfg.SrvCertLnk: oldCert, cfg.SrvKeyLnk: oldKey} {
			if err := restoreSymlink(target, link); err != nil {
				log.Errorf("failed to restore %s with: %v", link, err)
			}
		}
	}()

	if err := attemptWrite(certPath, []byte(oidevid), 0644); err != nil {
		return status.Errorf(codes.Internal, "failed to write oIDevID cert to %s: %v", certPath, err)
	}
	if err := atomicSetSrvCertTPMSigner(cfg, certPath); err != nil {
		return status.Errorf(codes.Internal, "failed to link oIDevID cert: %v", err)
	}
	if _, err := loadServingKeyPair(cfg, cfg.SrvCertLnk, cfg.SrvKeyLnk); err != nil {
		return status.Errorf(codes.Internal, "oIDevID cert is not servable: %v", err)
	}

	if srv.gnsiCertz != nil {
		if p := srv.gnsiCertz.profiles[defaultProfile]; p != nil {
			if p.ActiveEntities.Cert != nil && p.ActiveEntities.Cert.Final {
				p.LastEntities.Cert = p.ActiveEntities.Cert
			}
			p.ActiveEntities.Cert = &genericEntity{
				EType:     certType,
				CreatedOn: uint64(time.Now().Unix()),
				Version:   oIDevIDVersion,
				CertPath:  certPath,
				Final:     true,
			}
			writeEntityFreshness(p.ID, p.ActiveEntities.Cert)
			if cfg.CertzMetaFile != "" {
				if err := saveCertzMetadata(cfg.CertzMetaFile, srv.gnsiCertz.profiles); err != nil {
					log.V(1).Infof("failed to save certz metadata after oIDevID rotation: %v", err)
				}
			}
		}
	}
	committed = true
	log.V(1).Infof("Installed oIDevID cert %s in profile %q", certPath, defaultProfile)
	return nil
}

// readIdentityPublicKey returns the public key of a factory identity certificate.
func readIdentityPublicKey(cfg *Config, path string, nvIndex uint32) (crypto.PublicKey, error) {
	data, err := readIdentityCert(cfg, path, nvIndex)
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
