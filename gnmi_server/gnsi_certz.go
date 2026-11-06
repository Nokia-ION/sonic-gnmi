package gnmi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/golang/glog"
	certz "github.com/openconfig/gnsi/certz"
	"github.com/sonic-net/sonic-gnmi/common_utils"
	ssc "github.com/sonic-net/sonic-gnmi/sonic_service_client"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	defaultProfile string = "gnxi"
	defaultVersion string = "V1"
	// Prefixes for DB entries
	certTbl string = "CERT"
	certId  string = "certificate"
	tbId    string = "ca_trust_bundle"
	crlId   string = "certificate_revocation_list_bundle"
	authId  string = "authentication_policy"

	// Suffixes for DB entries
	versionFld string = "_version"
	createdFld string = "_created_on"

	// CRL organization
	crlDefault string = "crl" // translate between v0 and v1 organization
	crlFlush   string = "_flush"
	crlTmpDir  string = "tmp"

	backupExt      string = ".bak"
	credentialsTbl string = "CREDENTIALS"

	// Per-profile symlink and persist dirs so Rotate of a non-gnxi profile
	// (e.g. a custom SSL identity) does not retarget the gNMI listener certs.
	certzProfilesDir = "certz_profiles"
)

var persistentProfilesDir = "/etc/sonic/" + certzProfilesDir

var (
	certzMu               sync.Mutex
	csrPrefix             []byte = []byte("CSR1_")
	integrityManifestFile string = "/mbm/boot_manifest.cbor"
	// Mutex for DB writes
	dbWriteMutex sync.Mutex
)

type GNSICertzServer struct {
	*Server
	profiles map[string]*profile

	certz.UnimplementedCertzServer
}

type profile struct {
	ID             string      `json:"profile_id"`
	ActiveEntities entityGroup `json:"active"`
	LastEntities   entityGroup `json:"last_active"`
	generatedKey   []byte      `json:"-"`
}

type entityGroup struct {
	Cert        *genericEntity `json:"certificate"`
	TrustBundle *genericEntity `json:"trust_bundle"`
	CrlBundle   *genericEntity `json:"crl_bundle"`
	AuthPolicy  *genericEntity `json:"auth_policy"`
}

type genericEntity struct {
	EType     CertzType `json:type,omitempty`
	CreatedOn uint64    `json:created,omitempty`
	Version   string    `json:version,omitempty`
	CertPath  string    `json:cert_path,omitempty`
	KeyPath   string    `json:key_path,omitempty`
	Final     bool      `json:finalized,omitempty`
}

type CertzType int

const (
	certType CertzType = iota
	tbType
	crlType
	apType
)

func (ct CertzType) String() string {
	switch ct {
	case certType:
		return "Certificate"
	case tbType:
		return "TrustBundle"
	case crlType:
		return "CRLBundle"
	case apType:
		return "AuthPolicy"
	default:
		return "unknown"
	}

}

func NewGNSICertzServer(srv *Server) *GNSICertzServer {
	log.V(2).Info("Starting gNSI Certz Server")
	s := &GNSICertzServer{
		Server:   srv,
		profiles: make(map[string]*profile),
	}

	if srv.config.IntManFile != "" {
		integrityManifestFile = srv.config.IntManFile
	}
	log.V(2).Infof("Integrity Manifest File: %v", integrityManifestFile)

	if err := loadCertzMetadata(srv.config.CertzMetaFile, s.profiles); err != nil {
		log.V(0).Info(err)
	}
	if _, ok := s.profiles[defaultProfile]; !ok {
		// didn't find the default profile, so make it
		s.profiles[defaultProfile] = s.bootstrapDefaultProfile()
	}
	s.restoreCustomProfiles()

	for _, p := range s.profiles {
		writeEntityFreshness(p.ID, p.ActiveEntities.Cert)
		writeEntityFreshness(p.ID, p.ActiveEntities.TrustBundle)
		writeEntityFreshness(p.ID, p.ActiveEntities.CrlBundle)
		writeEntityFreshness(p.ID, p.ActiveEntities.AuthPolicy)
	}

	saveCertzMetadata(srv.config.CertzMetaFile, s.profiles)

	// Prepare CRL default dir if not present
	crlPath := filepath.Join(srv.config.CertCRLConfig, crlDefault)
	if _, err := os.Stat(crlPath); err != nil && os.IsNotExist(err) {
		log.V(2).Infof("Creating CRL Default path: %v", crlPath)
		if err := os.MkdirAll(crlPath, 0777); err != nil {
			log.V(1).Infof("Failed Creating CRL Default dir: %v", crlPath)
		}
	}
	flushPath := filepath.Join(srv.config.CertCRLConfig, crlDefault+crlFlush)
	if _, err := os.Stat(flushPath); err != nil && os.IsNotExist(err) {
		log.V(2).Infof("Creating CRL Flush path: %v", flushPath)
		if err := os.MkdirAll(flushPath, 0777); err != nil {
			log.V(1).Infof("Failed Creating CRL Flush dir: %v", flushPath)
		}
	}
	log.V(2).Info("Certz Server Ready")
	return s
}

func (srv *GNSICertzServer) AddProfile(ctx context.Context, req *certz.AddProfileRequest) (*certz.AddProfileResponse, error) {
	profileID := req.GetSslProfileId()
	log.V(2).Infof("Received AddProfile request for profile: %q", profileID)
	defer log.V(2).Infof("Finished AddProfile request for profile: %q", profileID)

	if profileID == "" {
		return nil, status.Error(codes.InvalidArgument, "ssl_profile_id cannot be empty")
	}

	if matched, _ := regexp.MatchString(`^[a-zA-Z0-9._-]+$`, profileID); !matched {
		return nil, status.Errorf(codes.InvalidArgument, "invalid ssl_profile_id: %q contains invalid characters. Only a-z, A-Z, 0-9, '.', '_', '-' are allowed", profileID)
	}

	if profileID == "." || profileID == ".." {
		return nil, status.Errorf(codes.InvalidArgument, "invalid ssl_profile_id: %q is reserved", profileID)
	}

	certzMu.Lock()
	defer certzMu.Unlock()

	if _, exists := srv.profiles[profileID]; exists {
		return nil, status.Errorf(codes.AlreadyExists, "profile %q already exists", profileID)
	}

	certLnk := getLinkPaths(srv.config, profileID).Cert
	baseDir := filepath.Dir(certLnk)
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create profile directory: %v", err)
	}

	timeNow := uint64(time.Now().Unix())
	p := &profile{
		ID: profileID,
		ActiveEntities: entityGroup{
			Cert:        &genericEntity{EType: certType, CreatedOn: timeNow, Version: defaultVersion, CertPath: "", KeyPath: "", Final: false},
			TrustBundle: &genericEntity{EType: tbType, CreatedOn: timeNow, Version: defaultVersion, CertPath: "", Final: false},
			CrlBundle:   &genericEntity{EType: crlType, CreatedOn: timeNow, Version: defaultVersion, CertPath: "", Final: false},
			AuthPolicy:  &genericEntity{EType: apType, CreatedOn: timeNow, Version: defaultVersion, CertPath: "", Final: false},
		},
	}
	p.LastEntities = entityGroup{}
	srv.profiles[profileID] = p

	if err := saveCertzMetadata(srv.config.CertzMetaFile, srv.profiles); err != nil {
		delete(srv.profiles, profileID)
		if errRm := os.RemoveAll(baseDir); errRm != nil {
			log.V(1).Infof("Failed to remove profile directory %q during rollback: %v", baseDir, errRm)
		}
		return nil, status.Errorf(codes.Internal, "failed to save profile metadata: %v", err)
	}

	log.V(2).Infof("Successfully added profile: %q", profileID)
	srv.addSslProfile(profileID)
	return &certz.AddProfileResponse{}, nil
}

func (srv *GNSICertzServer) DeleteProfile(ctx context.Context, req *certz.DeleteProfileRequest) (*certz.DeleteProfileResponse, error) {
	profileID := req.GetSslProfileId()
	log.V(2).Infof("Received DeleteProfile request for profile: %q", profileID)
	defer log.V(2).Infof("Finished DeleteProfile request for profile: %q", profileID)

	if profileID == "" {
		return nil, status.Error(codes.InvalidArgument, "ssl_profile_id cannot be empty")
	}

	if profileID == defaultProfile {
		return nil, status.Errorf(codes.InvalidArgument, "cannot delete default profile (%q)", defaultProfile)
	}

	certzMu.Lock()
	defer certzMu.Unlock()

	profile, exists := srv.profiles[profileID]
	if !exists {
		return nil, status.Errorf(codes.NotFound, "profile %q not found", profileID)
	}

	delete(srv.profiles, profileID)

	if err := saveCertzMetadata(srv.config.CertzMetaFile, srv.profiles); err != nil {
		srv.profiles[profileID] = profile
		return nil, status.Errorf(codes.Internal, "failed to save profile metadata: %v", err)
	}

	srv.removeEntityFiles(profile.ActiveEntities.Cert)
	srv.removeEntityFiles(profile.ActiveEntities.TrustBundle)
	srv.removeEntityFiles(profile.LastEntities.Cert)
	srv.removeEntityFiles(profile.LastEntities.TrustBundle)

	profileDir := filepath.Join(filepath.Dir(srv.config.SrvCertLnk), certzProfilesDir, profileID)
	if err := os.RemoveAll(profileDir); err != nil {
		log.V(1).Infof("Failed to remove profile symlink directory %q: %v", profileDir, err)
	}
	persistDir := filepath.Join(persistentProfilesDir, profileID)
	if err := os.RemoveAll(persistDir); err != nil {
		log.V(1).Infof("Failed to remove profile persistent directory %q: %v", persistDir, err)
	}

	if err := deleteCredentialsMetadataFromDB(certTbl, profileID); err != nil {
		log.V(1).Infof("Failed to delete credentials metadata from DB for profile %q: %v", profileID, err)
	}

	srv.deleteSslProfile(profileID)
	unbindProfile(profileID)

	return &certz.DeleteProfileResponse{}, nil
}

func (srv *GNSICertzServer) GetProfileList(ctx context.Context, req *certz.GetProfileListRequest) (*certz.GetProfileListResponse, error) {
	log.V(2).Info("Received GetProfileList request")
	defer log.V(2).Info("Finished GetProfileList request")

	certzMu.Lock()
	defer certzMu.Unlock()

	profileIDs := make([]string, 0, len(srv.profiles))
	for ID := range srv.profiles {
		profileIDs = append(profileIDs, ID)
	}
	slices.Sort(profileIDs)

	return &certz.GetProfileListResponse{
		SslProfileIds: profileIDs,
	}, nil
}
func (srv *GNSICertzServer) CanGenerateCSR(ctx context.Context, req *certz.CanGenerateCSRRequest) (*certz.CanGenerateCSRResponse, error) {
	if req.GetParams().GetCommonName() == "" {
		return &certz.CanGenerateCSRResponse{CanGenerate: false}, nil
	}
	return &certz.CanGenerateCSRResponse{CanGenerate: true}, nil
}

func (srv *GNSICertzServer) bootstrapDefaultProfile() *profile {
	log.V(2).Info("Bootstrapping default profile")
	time := uint64(time.Now().UnixNano())
	keyPath := ""
	if !tpmTLSEnabled(srv.config) || linkExists(srv.config.SrvKeyLnk) {
		keyPath = restoreFromFile(srv.config.SrvKeyLnk, srv.config.SrvKeyFile)
	}

	return &profile{
		ID: defaultProfile,
		ActiveEntities: entityGroup{
			Cert: &genericEntity{
				EType:     certType,
				CreatedOn: time,
				Version:   "V1",
				CertPath:  restoreFromFile(srv.config.SrvCertLnk, srv.config.SrvCertFile),
				KeyPath:   keyPath,
				Final:     true,
			},
			TrustBundle: &genericEntity{
				EType:     tbType,
				CreatedOn: time,
				Version:   "V1",
				CertPath:  restoreFromFile(srv.config.CaCertLnk, srv.config.CaCertFile),
				Final:     true,
			},
			CrlBundle: &genericEntity{
				EType:     crlType,
				CreatedOn: time,
				Version:   "V1",
				CertPath:  srv.config.CertCRLConfig,
				Final:     true,
			},
			AuthPolicy: &genericEntity{
				EType:     apType,
				CreatedOn: time,
				Version:   "V1",
				CertPath:  srv.config.FedPolicyFile,
				Final:     true,
			},
		},
		LastEntities: entityGroup{
			Cert:        &genericEntity{},
			TrustBundle: &genericEntity{},
			CrlBundle:   &genericEntity{},
			AuthPolicy:  &genericEntity{},
		},
	}
}

func resolveSymlinkTarget(linkPath string) string {
	if cp, err := filepath.EvalSymlinks(linkPath); err == nil {
		return cp
	}
	if _, err := os.Lstat(linkPath); os.IsNotExist(err) {
		return ""
	}
	if resolved := traverseSymlink(linkPath); resolved != linkPath {
		return resolved
	}
	return ""
}

func restoreCustomCA(profileID, link, persistPath string) string {
	if _, err := os.Stat(persistPath); err == nil {
		log.V(2).Infof("Restoring CA from persistent file: %s", persistPath)
		return persistPath
	}
	if realPath, err := filepath.EvalSymlinks(link); err == nil {
		log.V(2).Infof("Restoring CA from symlink target: %s", realPath)
		return realPath
	}
	log.V(1).Infof("No CA found in persistent path for profile %s", profileID)
	return ""
}

func (srv *GNSICertzServer) restoreCustomProfile(profileID string) *profile {
	log.V(2).Infof("Restoring custom profile: %s", profileID)
	timeNow := uint64(time.Now().Unix())

	paths := getLinkPaths(srv.config, profileID)
	persistPath := filepath.Join(persistentProfilesDir, profileID, "ca")
	caPath := restoreCustomCA(profileID, paths.CA, persistPath)
	p := &profile{
		ID: profileID,
		ActiveEntities: entityGroup{
			Cert: &genericEntity{
				EType:     certType,
				CreatedOn: timeNow,
				Version:   defaultVersion,
				CertPath:  resolveSymlinkTarget(paths.Cert),
				KeyPath:   resolveSymlinkTarget(paths.Key),
				Final:     true,
			},
			TrustBundle: &genericEntity{
				EType:     tbType,
				CreatedOn: timeNow,
				Version:   defaultVersion,
				CertPath:  caPath,
				Final:     true,
			},
			CrlBundle: &genericEntity{
				EType:     crlType,
				CreatedOn: timeNow,
				Version:   defaultVersion,
				CertPath:  paths.CRL,
				Final:     true,
			},
			AuthPolicy: &genericEntity{
				EType:     apType,
				CreatedOn: timeNow,
				Version:   defaultVersion,
				Final:     true,
			},
		},
	}
	p.LastEntities = entityGroup{}
	return p
}

func (srv *GNSICertzServer) restoreCustomProfiles() {
	log.V(2).Info("Restoring custom profiles from persistent storage")
	files, err := os.ReadDir(persistentProfilesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		log.V(1).Infof("Failed to read persistent profiles dir: %v", err)
		return
	}
	for _, f := range files {
		if !f.IsDir() {
			continue
		}
		profileID := f.Name()
		if profileID == defaultProfile {
			continue
		}
		if _, ok := srv.profiles[profileID]; !ok {
			srv.profiles[profileID] = srv.restoreCustomProfile(profileID)
		}
	}
}

// Rotate implements corresponding RPC.
func (srv *GNSICertzServer) Rotate(stream certz.Certz_RotateServer) error {
	ctx := stream.Context()
	_, err := authenticate(srv.config, ctx, "gnoi", false)
	if err != nil {
		return err
	}

	session := time.Now().Nanosecond()
	if !certzMu.TryLock() {
		return status.Error(codes.Aborted, "concurrent certz.Rotate RPCs are not allowed")
	}
	defer certzMu.Unlock()

	log.V(2).Infof("[%v]gNSI: Begin certz.Rotate", session)
	defer log.V(2).Infof("[%v]gNSI: End certz.Rotate", session)

	var profileId string
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			log.V(0).Infof("[%v]gNSI: Received unexpected EOF", session)
			// Connection closed without Finalize message. Revert all changes made until now.
			srv.revertProfile(profileId)
			return status.Error(codes.Aborted, "No Finalize message")
		}
		if err != nil {
			log.V(0).Infof("[%v]gNSI: Received error: %v", session, err)
			// Connection closed without Finalize message. Revert all changes made until now.
			srv.revertProfile(profileId)
			return status.Errorf(codes.Aborted, "Stream recv err: %v", err)
		}
		if endReq := req.GetFinalizeRotation(); endReq != nil {
			// This is the last message. All changes are final.
			log.V(0).Infof("[%v]gNSI: Received Finalize: %v", session, endReq)
			// The new credentials have been confirmed to be correct. Remove the old ones.
			if err := srv.finalizeProfile(profileId); err != nil {
				return status.Errorf(codes.Unknown, "Failed to remove the old credentials: %v", err)
			}
			log.V(2).Infof("[%v]gNSI: Rotation Finalized", session)
			return nil
		}
		if profileId == "" {
			profileId = defaultProfile
			if reqID := req.GetSslProfileId(); reqID != "" {
				profileId = reqID
			}
			if profileId != defaultProfile {
				srv.sslProfileCheckpoint(ssc.CredzCPCreate, profileId)
			}
		}
		log.V(2).Infof("[%v]gNSI: Rotating profile: %s", session, profileId)
		resp, err := srv.processRotateRequest(profileId, req)
		if err != nil {
			srv.revertProfile(profileId)
			return status.Errorf(codes.Aborted, "Process err: %v", err)
		}
		// Send confirmation that the UploadRequest was processed.
		if err := stream.Send(resp); err != nil {
			srv.revertProfile(profileId)
			return status.Errorf(codes.Aborted, "Stream send err: %v", err)
		}
	}
}

func (srv *GNSICertzServer) processRotateRequest(profileID string, req *certz.RotateCertificateRequest) (*certz.RotateCertificateResponse, error) {
	if _, ok := srv.profiles[profileID]; !ok {
		return &certz.RotateCertificateResponse{}, status.Errorf(codes.InvalidArgument, "Rotate requested with invalid ssl_profile_id: %s", profileID)
	}
	rotateResp := certz.RotateCertificateResponse{}
	switch req.RotateRequest.(type) {
	case *certz.RotateCertificateRequest_GenerateCsr:
		resp, err := srv.doGenerateCsr(profileID, req.GetGenerateCsr())
		if err != nil {
			return nil, err
		}
		rotateResp.RotateResponse = &certz.RotateCertificateResponse_GeneratedCsr{GeneratedCsr: resp}
	case *certz.RotateCertificateRequest_Certificates:
		resp, err := srv.doUpload(req.GetCertificates(), req.GetForceOverwrite(), profileID)
		if err != nil {
			return nil, err
		}
		rotateResp.RotateResponse = &certz.RotateCertificateResponse_Certificates{Certificates: resp}
	default:
		return nil, status.Errorf(codes.Aborted, "Invalid RotateRequest: %T", req.RotateRequest)
	}
	return &rotateResp, nil
}

func (srv *GNSICertzServer) doGenerateCsr(profileID string, req *certz.GenerateCSRRequest) (*certz.GenerateCSRResponse, error) {
	log.V(2).Info("Generating Csr")

	keySize, sigAlgo := parseCSRSuite(req.GetParams().GetCsrSuite())
	// Fields the request leaves empty are omitted: an empty attribute, such
	// as a Country that is not two letters, is invalid X.509 and CAs reject it.
	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         req.GetParams().CommonName,
			Country:            nonEmpty(req.GetParams().Country),
			Province:           nonEmpty(req.GetParams().State),
			Locality:           nonEmpty(req.GetParams().City),
			Organization:       nonEmpty(req.GetParams().Organization),
			OrganizationalUnit: nonEmpty(req.GetParams().OrganizationalUnit),
		},
		SignatureAlgorithm: sigAlgo,
	}

	var privKey any
	var err error
	switch sigAlgo {
	case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA:
		log.V(2).Infof("Generating keys for RSA: %v", req.GetParams().GetCsrSuite().String())
		privKey, err = rsa.GenerateKey(rand.Reader, keySize)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "GenerateKey failed: %v", err)
		}
	case x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
		log.V(2).Infof("Generating keys for ECDSA: %v", req.GetParams().GetCsrSuite().String())
		var curve elliptic.Curve
		switch keySize {
		case 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		default:
			return nil, status.Errorf(codes.InvalidArgument, "Unsupported key size for ECDSA: %v", keySize)
		}
		privKey, err = ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "GenerateKey failed: %v", err)
		}
	case x509.PureEd25519:
		fallthrough
	case x509.UnknownSignatureAlgorithm:
		fallthrough
	default:
		return nil, status.Errorf(codes.InvalidArgument, "Unsupported Algorithm: %v", sigAlgo.String())

	}

	csrCert, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "CreateCertificateRequest failed: %v", err)
	}
	csr := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE REQUEST", Bytes: csrCert,
	})
	// Save the CSR Private Key
	key, err := x509.MarshalPKCS8PrivateKey(privKey)
	srv.profiles[profileID].generatedKey = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})

	return &certz.GenerateCSRResponse{
		CertificateSigningRequest: &certz.CertificateSigningRequest{
			Type:                      certz.CertificateType_CERTIFICATE_TYPE_X509,
			Encoding:                  certz.CertificateEncoding_CERTIFICATE_ENCODING_PEM,
			CertificateSigningRequest: csr,
		},
	}, nil
}

// nonEmpty returns s as a one-element slice, or nil if s is empty.
func nonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}

func (srv *GNSICertzServer) doUpload(req *certz.UploadRequest, overwrite bool, profileID string) (*certz.UploadResponse, error) {
	muPath.Lock()
	defer muPath.Unlock()

	if len(req.GetEntities()) == 0 {
		return nil, status.Errorf(codes.InvalidArgument, "entity cannot be empty")
	}
	for _, entityMsg := range req.GetEntities() {
		if entityMsg.GetCreatedOn() == 0 {
			return nil, status.Errorf(codes.InvalidArgument, "created_on cannot be empty")
		}
		if entityMsg.GetVersion() == "" {
			return nil, status.Errorf(codes.InvalidArgument, "version cannot be empty")
		}

		var expEntity *genericEntity
		// Entity is OneOf the following
		if c := entityMsg.GetCertificateChain(); c != nil {
			expEntity = srv.newGenericEntity(certType, profileID, entityMsg)
		}
		if tb := entityMsg.GetTrustBundle(); tb != nil {
			expEntity = srv.newGenericEntity(tbType, profileID, entityMsg)
		}
		if crl := entityMsg.GetCertificateRevocationListBundle(); crl != nil {
			if srv.Server.config.CertCRLConfig == "" {
				return nil, status.Error(codes.Aborted, "CRL not configured")
			}
			expEntity = srv.newGenericEntity(crlType, profileID, entityMsg)
		}
		if ap := entityMsg.GetAuthenticationPolicy(); ap != nil {
			expEntity = srv.newGenericEntity(apType, profileID, entityMsg)
		}
		if expEntity == nil {
			return nil, status.Errorf(codes.Internal, "failed to find entity type: %+v", entityMsg)
		}

		if !overwrite {
			if err := srv.entityAlreadyActive(profileID, expEntity); err != nil {
				return nil, err
			}
		}
		if err := srv.saveEntities(profileID, entityMsg, expEntity); err != nil {
			return nil, status.Errorf(codes.Aborted, "Entity save err: %v", err)
		}
		if err := srv.activateEntity(profileID, expEntity); err != nil {
			return nil, status.Errorf(codes.Aborted, "Entity activate err: %v", err)
		}
	}
	return &certz.UploadResponse{}, nil
}

func (srv *GNSICertzServer) newGenericEntity(eType CertzType, profileID string, entityMsg *certz.Entity) *genericEntity {
	ver := strings.ReplaceAll(entityMsg.GetVersion(), " ", "-")
	keyPath := ""
	certPath := ""
	t := time.Now().UnixNano()

	paths := getLinkPaths(srv.config, profileID)
	certLnkDir := filepath.Dir(paths.Cert)
	keyLnkDir := filepath.Dir(paths.Key)
	caLnkDir := filepath.Dir(paths.CA)

	switch eType {
	case certType:
		certPath = fmt.Sprintf("%v/%v_%v_%d_cert.pem", certLnkDir, profileID, ver, t)
		keyPath = fmt.Sprintf("%v/%v_%v_%d_key.pem", keyLnkDir, profileID, ver, t)
	case tbType:
		certPath = fmt.Sprintf("%v/ca_%v_%v_%d_bundle.pem", caLnkDir, profileID, ver, t)
	case crlType:
		certPath = paths.CRL
		if err := os.MkdirAll(certPath, 0777); err != nil {
			log.V(1).Infof("Failed creating CRL dir: %v", certPath)
		}
	case apType:
		certPath = srv.config.FedPolicyFile
	}
	log.V(2).Infof("creating new Entity: %+v", entityMsg)
	return &genericEntity{
		EType:     eType,
		CreatedOn: entityMsg.GetCreatedOn(),
		Version:   entityMsg.GetVersion(),
		CertPath:  certPath,
		KeyPath:   keyPath,
	}
}

func (srv *GNSICertzServer) activateEntity(profileID string, entity *genericEntity) error {
	profile, ok := srv.profiles[profileID]
	if !ok || profile == nil {
		return status.Errorf(codes.InvalidArgument, "Rotate requested with invalid ssl_profile_id: %s", profileID)
	}
	log.V(2).Infof("Activating: %+v", entity)
	switch entity.EType {
	case certType:
		if err := atomicSetSrvCertKeyPair(srv.config, profileID, entity.CertPath, entity.KeyPath); err != nil {
			return err
		}
		if profile.ActiveEntities.Cert != nil && profile.ActiveEntities.Cert.Final {
			profile.LastEntities.Cert = profile.ActiveEntities.Cert
		}
		profile.ActiveEntities.Cert = entity

	case tbType:
		if err := atomicSetCACert(srv.config, profileID, entity.CertPath); err != nil {
			return err
		}
		if profile.ActiveEntities.TrustBundle != nil && profile.ActiveEntities.TrustBundle.Final {
			profile.LastEntities.TrustBundle = profile.ActiveEntities.TrustBundle
		}
		profile.ActiveEntities.TrustBundle = entity

	case crlType:
		if profile.ActiveEntities.CrlBundle != nil && profile.ActiveEntities.CrlBundle.Final {
			profile.LastEntities.CrlBundle = profile.ActiveEntities.CrlBundle
		}
		profile.ActiveEntities.CrlBundle = entity

	case apType:
		if profile.ActiveEntities.AuthPolicy != nil && profile.ActiveEntities.AuthPolicy.Final {
			profile.LastEntities.AuthPolicy = profile.ActiveEntities.AuthPolicy
		}
		profile.ActiveEntities.AuthPolicy = entity
	}

	writeEntityFreshness(profileID, entity)
	return nil
}

func (srv *GNSICertzServer) saveEntities(profileID string, entityMsg *certz.Entity, expEntity *genericEntity) error {
	log.V(2).Infof("Saving entity: %+v", expEntity)
	switch expEntity.EType {
	case certType:
		cert, key, err := srv.readCertChain(profileID, entityMsg.GetCertificateChain())
		if err != nil {
			return err
		}
		if e := attemptWrite(expEntity.KeyPath, key, 0600); e != nil {
			return e
		}
		return attemptWrite(expEntity.CertPath, cert, 0600)
	case tbType:
		tb := entityMsg.GetTrustBundle().GetCertificate()
		if tb.Type != certz.CertificateType_CERTIFICATE_TYPE_X509 {
			return status.Errorf(codes.InvalidArgument, "trustBundle type has to be X.509")
		}
		if tb.Encoding != certz.CertificateEncoding_CERTIFICATE_ENCODING_PEM {
			return status.Errorf(codes.InvalidArgument, "trustBundle encoding has to be PEM")
		}
		bundle := certPEM(tb)
		if len(bundle) == 0 {
			return status.Errorf(codes.InvalidArgument, "trustBundle cannot be empty")
		}
		if err := attemptWrite(expEntity.CertPath, bundle, 0600); err != nil {
			return err
		}
		if profileID != defaultProfile {
			persistDir := filepath.Join(persistentProfilesDir, profileID)
			if err := os.MkdirAll(persistDir, 0755); err != nil {
				log.V(1).Infof("Failed to create persist dir: %v", err)
			} else {
				persistPath := filepath.Join(persistDir, "ca")
				log.V(2).Infof("Persisting TrustBundle to %s", persistPath)
				if err := attemptWrite(persistPath, bundle, 0600); err != nil {
					log.V(1).Infof("Failed to persist TrustBundle: %v", err)
				}
			}
		}
		return nil
	case crlType:
		if err := rotateCRLBundle(entityMsg.GetCertificateRevocationListBundle(), expEntity.CertPath); err != nil {
			return status.Errorf(codes.Aborted, "%s", err.Error())
		}
		return nil
	case apType:
		if _, state := os.Lstat(expEntity.CertPath + backupExt); os.IsNotExist(state) {
			log.V(2).Info("Backing up Auth Policy")
			if err := os.Rename(expEntity.CertPath, expEntity.CertPath+backupExt); err != nil {
				return err
			}
		}
		if err := attemptWrite(expEntity.CertPath, entityMsg.GetAuthenticationPolicy().GetSerialized().GetValue(), 0600); err != nil {
			log.V(1).Infof("Failed to save Auth Policy: %v", err)
			if e := os.Rename(expEntity.CertPath+backupExt, expEntity.CertPath); e != nil {
				log.V(1).Infof("Failed to restore Auto Policy Backup: %v", e)
			}
			return err
		}
		return nil
	}
	return status.Errorf(codes.Internal, "failed to find entity type: %+v", entityMsg)
}

func (srv *GNSICertzServer) readCertChain(profileID string, certChain *certz.CertificateChain) ( /*cert*/ []byte /*key*/, []byte, error) {
	// step through the certificate chain and append each parent
	if certChain.GetCertificate() == nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "Missing Certificate")
	}
	if certChain.GetCertificate().Type != certz.CertificateType_CERTIFICATE_TYPE_X509 {
		return nil, nil, status.Errorf(codes.InvalidArgument, "certificate type has to be X.509")
	}
	if certChain.GetCertificate().Encoding != certz.CertificateEncoding_CERTIFICATE_ENCODING_PEM {
		return nil, nil, status.Errorf(codes.InvalidArgument, "certificate encoding has to be PEM")
	}
	if len(certPEM(certChain.GetCertificate())) == 0 {
		return nil, nil, status.Errorf(codes.InvalidArgument, "Missing Cert data")
	}
	cert := append(certPEM(certChain.GetCertificate()), byte('\n'))
	key := keyPEM(certChain.GetCertificate())
	if len(key) == 0 {
		if srv.profiles[profileID].generatedKey == nil {
			return nil, nil, status.Errorf(codes.InvalidArgument, "Missing Key")
		}
		log.V(2).Info("No key provided; Using generated key.")
		key = srv.profiles[profileID].generatedKey
	}

	certChain = certChain.GetParent()
	for certChain != nil {
		if certChain.GetCertificate().Type != certz.CertificateType_CERTIFICATE_TYPE_X509 {
			return nil, nil, status.Errorf(codes.InvalidArgument, "certificate type has to be X.509")
		}
		if certChain.GetCertificate().Encoding != certz.CertificateEncoding_CERTIFICATE_ENCODING_PEM {
			return nil, nil, status.Errorf(codes.InvalidArgument, "certificate encoding has to be PEM")
		}
		//replace with slices.Concat once go1.22 is available
		cert = append(cert, append(certPEM(certChain.GetCertificate()), byte('\n'))...)

		certChain = certChain.GetParent()
	}
	if err := verifyCertChain(cert, key); err != nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	return cert, key, nil
}

// verifyCertChain checks that key is the private key of the leaf in chain,
// and that each certificate in chain is signed by the one after it. An upload
// is served as soon as it is activated, so a bad chain or key would break
// every new TLS connection.
func verifyCertChain(chain, key []byte) error {
	pair, err := tls.X509KeyPair(chain, key)
	if err != nil {
		return fmt.Errorf("invalid certificate or private key: %w", err)
	}
	certs := make([]*x509.Certificate, len(pair.Certificate))
	for i, der := range pair.Certificate {
		if certs[i], err = x509.ParseCertificate(der); err != nil {
			return fmt.Errorf("parse certificate %d of the chain: %w", i, err)
		}
	}
	for i := 0; i+1 < len(certs); i++ {
		if err := certs[i].CheckSignatureFrom(certs[i+1]); err != nil {
			return fmt.Errorf("certificate %q is not signed by its parent %q: %w",
				certs[i].Subject, certs[i+1].Subject, err)
		}
	}
	return nil
}

// certPEM returns raw_certificate, or the deprecated certificate field that
// older clients still send.
func certPEM(c *certz.Certificate) []byte {
	if raw := c.GetRawCertificate(); len(raw) > 0 {
		return raw
	}
	return c.GetCertificate()
}

// keyPEM returns raw_private_key, or the deprecated private_key field.
func keyPEM(c *certz.Certificate) []byte {
	if raw := c.GetRawPrivateKey(); len(raw) > 0 {
		return raw
	}
	return c.GetPrivateKey()
}

func (srv *GNSICertzServer) revertProfile(profileID string) {
	log.V(2).Infof("Reverting to last known good gRPC credentials for profile=%v", profileID)
	if profileID == "" {
		profileID = defaultProfile
		log.V(2).Infof("Reverting default profile: %v", defaultProfile)
	}
	profile, ok := srv.profiles[profileID]
	if !ok || profile == nil {
		log.V(2).Infof("No profile to revert: %v", profileID)
		return
	}
	muPath.Lock()
	if profile.ActiveEntities.Cert != nil && !profile.ActiveEntities.Cert.Final {
		log.V(2).Info("Rollback Cert")
		rollbackCert := ""
		rollbackKey := ""
		if profile.LastEntities.Cert != nil {
			rollbackCert = profile.LastEntities.Cert.CertPath
			rollbackKey = profile.LastEntities.Cert.KeyPath
		}
		var err error
		if profileID == defaultProfile && tpmTLSEnabled(srv.config) && rollbackCert != "" && rollbackKey == "" {
			err = atomicSetSrvCertTPMSigner(srv.config, rollbackCert)
		} else {
			err = atomicSetSrvCertKeyPair(srv.config, profileID, rollbackCert, rollbackKey)
		}
		if err != nil {
			log.V(0).Infof("Failed to revert certificate files: %v", err)
		}
		if profile.LastEntities.Cert != nil {
			writeEntityFreshness(profileID, profile.LastEntities.Cert)
			srv.removeEntityFiles(profile.ActiveEntities.Cert)
			profile.ActiveEntities.Cert = profile.LastEntities.Cert
		}
	}
	if profile.ActiveEntities.TrustBundle != nil && !profile.ActiveEntities.TrustBundle.Final {
		log.V(2).Info("Rollback TB")
		rollbackCA := ""
		if profile.LastEntities.TrustBundle != nil {
			rollbackCA = profile.LastEntities.TrustBundle.CertPath
		}
		if err := atomicSetCACert(srv.config, profileID, rollbackCA); err != nil {
			log.V(0).Infof("Failed to revert trust bundle file: %v", err)
		}
		if profile.LastEntities.TrustBundle != nil {
			writeEntityFreshness(profileID, profile.LastEntities.TrustBundle)
			srv.removeEntityFiles(profile.ActiveEntities.TrustBundle)
			profile.ActiveEntities.TrustBundle = profile.LastEntities.TrustBundle
		}
	}
	if profile.ActiveEntities.CrlBundle != nil && !profile.ActiveEntities.CrlBundle.Final {
		log.V(2).Info("Rollback CRL")
		path := getLinkPaths(srv.config, profileID).CRL
		copyCRLBundle(path+crlFlush, path)
		if profile.LastEntities.CrlBundle != nil {
			writeEntityFreshness(profileID, profile.LastEntities.CrlBundle)
			profile.ActiveEntities.CrlBundle = profile.LastEntities.CrlBundle
		}
	}
	if profile.ActiveEntities.AuthPolicy != nil && !profile.ActiveEntities.AuthPolicy.Final {
		log.V(2).Info("Rollback AP")
		if err := os.Rename(profile.ActiveEntities.AuthPolicy.CertPath+backupExt, profile.ActiveEntities.AuthPolicy.CertPath); err != nil {
			log.V(0).Infof("Failed to revert Auth Policy: %v", err)
		}
		if profile.LastEntities.AuthPolicy != nil {
			writeEntityFreshness(profileID, profile.LastEntities.AuthPolicy)
			profile.ActiveEntities.AuthPolicy = profile.LastEntities.AuthPolicy
		}
	}
	if err := saveCertzMetadata(srv.config.CertzMetaFile, srv.profiles); err != nil {
		log.V(0).Infof("Failed to save certz metadata after revert: %v", err)
	}
	muPath.Unlock()
	srv.sslProfileCheckpoint(ssc.CredzCPRestore, profileID)
	srv.sslProfileCheckpoint(ssc.CredzCPDelete, profileID)
}

func (srv *GNSICertzServer) finalizeProfile(profileID string) error {
	log.V(2).Infof("Finalizing gRPC credentials for profile=%v", profileID)
	profile, ok := srv.profiles[profileID]
	if !ok || profile == nil {
		return status.Errorf(codes.InvalidArgument, "Finalize requested with invalid ssl_profile_id: %s", profileID)
	}
	if profile.ActiveEntities.Cert != nil && !profile.ActiveEntities.Cert.Final {
		srv.removeEntityFiles(profile.LastEntities.Cert)
		profile.ActiveEntities.Cert.Final = true
	}
	profile.LastEntities.Cert = profile.ActiveEntities.Cert

	if profile.ActiveEntities.TrustBundle != nil && !profile.ActiveEntities.TrustBundle.Final {
		srv.removeEntityFiles(profile.LastEntities.TrustBundle)
		profile.ActiveEntities.TrustBundle.Final = true
	}
	profile.LastEntities.TrustBundle = profile.ActiveEntities.TrustBundle

	if profile.ActiveEntities.CrlBundle != nil && !profile.ActiveEntities.CrlBundle.Final {
		path := getLinkPaths(srv.config, profileID).CRL
		copyCRLBundle(path, path+crlFlush)
		profile.ActiveEntities.CrlBundle.Final = true
		profile.LastEntities.CrlBundle = profile.ActiveEntities.CrlBundle
	}

	if profile.ActiveEntities.AuthPolicy != nil && !profile.ActiveEntities.AuthPolicy.Final {
		log.V(2).Info("Finalize AP")
		if err := os.Remove(profile.ActiveEntities.AuthPolicy.CertPath + backupExt); err != nil {
			log.V(1).Infof("Auth Policy backup was lost: %v", err)
		}
		profile.ActiveEntities.AuthPolicy.Final = true
	}
	profile.LastEntities.AuthPolicy = profile.ActiveEntities.AuthPolicy

	if err := saveCertzMetadata(srv.config.CertzMetaFile, srv.profiles); err != nil {
		return err
	}

	// Stage host-readable PEMs via host-services ssl_profile. Failure is
	// logged, not fatal: Certz has already stored the profile, and consumers
	// bind the id from CONFIG_DB (syslog uses SYSLOG_SERVER.tls_profile_id).
	srv.installSslProfile(profileID)
	srv.sslProfileCheckpoint(ssc.CredzCPDelete, profileID)
	return nil
}

func writeEntityFreshness(profileID string, entity *genericEntity) {
	if entity == nil {
		log.V(2).Infof("Skipping db write for empty entity in profile %s", profileID)
		return
	}
	log.V(2).Infof("Writing %s profile to DB: %+v", profileID, entity)
	var vFld string
	var cFld string

	//	CreatedOn is received as seconds but should be stored as NanoSeconds
	created := strconv.FormatUint(entity.CreatedOn, 10) + "000000000"

	switch entity.EType {
	case certType:
		vFld = certId + versionFld
		cFld = certId + createdFld
	case tbType:
		vFld = tbId + versionFld
		cFld = tbId + createdFld
	case crlType:
		vFld = crlId + versionFld
		cFld = crlId + createdFld
	case apType:
		vFld = authId + versionFld
		cFld = authId + createdFld
	default:
		log.V(0).Infof("Unknown entity in profile: %s : %+v", profileID, entity)
	}

	writeCredentialsMetadataToDB(certTbl, profileID, cFld, created)
	writeCredentialsMetadataToDB(certTbl, profileID, vFld, entity.Version)
}

func saveCertzMetadata(path string, profiles map[string]*profile) error {
	log.V(2).Info("Saving gRPC credentials metadata.")
	data, err := json.Marshal(profiles)
	if err != nil {
		return err
	}
	log.V(2).Infof("Certz Metadata:\n%v", string(data))
	return attemptWrite(path, data, 0644)
}

func loadCertzMetadata(path string, profiles map[string]*profile) error {
	log.V(2).Infof("Loading metadata from `%v`...\n", path)
	bytes, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(bytes, &profiles); err != nil {
		return err
	}
	for k, p := range profiles {
		if err := validateProfileExists(*p); err != nil {
			log.V(1).Infof("%v profile error: %v", k, err)
			delete(profiles, k)
		}
		log.V(2).Infof("Added %s profile: %+v", k, *p)
	}
	return nil
}

func validateProfileExists(profile profile) error {
	if profile.ID == "" {
		return status.Errorf(codes.NotFound, "cannot validate empty profile")
	}
	if profile.ActiveEntities.Cert != nil && profile.ActiveEntities.Cert.CertPath != "" {
		if _, err := os.Lstat(profile.ActiveEntities.Cert.CertPath); os.IsNotExist(err) {
			return status.Errorf(codes.NotFound, "Cert '%v': '%v' does not exist", profile.ID, profile.ActiveEntities.Cert.CertPath)
		}
	}
	if profile.ActiveEntities.Cert != nil && profile.ActiveEntities.Cert.KeyPath != "" {
		if _, err := os.Lstat(profile.ActiveEntities.Cert.KeyPath); os.IsNotExist(err) {
			return status.Errorf(codes.NotFound, "Key '%v': '%v' does not exist", profile.ID, profile.ActiveEntities.Cert.KeyPath)
		}
	}
	if profile.ActiveEntities.TrustBundle != nil && profile.ActiveEntities.TrustBundle.CertPath != "" {
		if _, err := os.Lstat(profile.ActiveEntities.TrustBundle.CertPath); os.IsNotExist(err) {
			return status.Errorf(codes.NotFound, "TB '%v': '%v' does not exist", profile.ID, profile.ActiveEntities.TrustBundle.CertPath)
		}
	}
	return nil
}

func (srv *GNSICertzServer) entityAlreadyActive(profileID string, entity *genericEntity) error {
	profile, ok := srv.profiles[profileID]
	if !ok {
		return nil
	}
	switch entity.EType {
	case certType:
		if profile.ActiveEntities.Cert != nil && entity.Version == profile.ActiveEntities.Cert.Version {
			return status.Errorf(codes.AlreadyExists, "%s with profile=`%s` and version=`%v` already exists", entity.EType, profileID, entity.Version)
		}
	case tbType:
		if profile.ActiveEntities.TrustBundle != nil && entity.Version == profile.ActiveEntities.TrustBundle.Version {
			return status.Errorf(codes.AlreadyExists, "%s with profile=`%s` and version=`%v` already exists", entity.EType, profileID, entity.Version)
		}
	case crlType:
		if profile.ActiveEntities.CrlBundle != nil && entity.Version == profile.ActiveEntities.CrlBundle.Version {
			return status.Errorf(codes.AlreadyExists, "%s with profile=`%s` and version=`%v` already exists", entity.EType, profileID, entity.Version)
		}
	case apType:
		if profile.ActiveEntities.AuthPolicy != nil && entity.Version == profile.ActiveEntities.AuthPolicy.Version {
			return status.Errorf(codes.AlreadyExists, "%s with profile=`%s` and version=`%v` already exists", entity.EType, profileID, entity.Version)
		}
	}
	return nil
}

func rotateCRLBundle(crl *certz.CertificateRevocationListBundle, path string) error {
	log.V(2).Infof("Saving CRL to: %s", path)
	certs := crl.GetCertificateRevocationLists()
	if certs == nil || len(certs) == 0 {
		return status.Errorf(codes.InvalidArgument, "CRL bundle cannot be empty")
	}
	for i, c := range certs {
		if t := c.GetType(); t != certz.CertificateType_CERTIFICATE_TYPE_X509 {
			return status.Errorf(codes.InvalidArgument, "CRL type has to be X.509")
		}
		if c.GetEncoding() != certz.CertificateEncoding_CERTIFICATE_ENCODING_PEM {
			return status.Errorf(codes.InvalidArgument, "CRL encoding has to be PEM")
		}
		if len(c.GetCertificateRevocationList()) == 0 {
			return status.Errorf(codes.InvalidArgument, "CRL #%v is empty", i)
		}
		der, _ := pem.Decode(c.GetCertificateRevocationList())
		if _, err := x509.ParseRevocationList(der.Bytes); err != nil {
			return status.Errorf(codes.InvalidArgument, "CRL failed to parse: %v", err)
		}
		if err := attemptWrite(filepath.Join(path, c.GetId()), c.CertificateRevocationList, 0644); err != nil {
			return status.Errorf(codes.FailedPrecondition, "CRL %v write failed: %v", c.GetId(), err)
		}
	}

	dstFiles, err := os.ReadDir(path)
	if err != nil {
		log.V(1).Info(err)
	}
	for _, file := range dstFiles {
		if err := os.Remove(filepath.Join(path, file.Name())); err != nil {
			log.V(1).Info(err)
		}
	}
	for _, c := range certs {
		if err := attemptWrite(filepath.Join(path, c.GetId()), c.CertificateRevocationList, 0644); err != nil {
			return status.Errorf(codes.FailedPrecondition, "CRL %v write failed: %v", c.GetId(), err)
		}
	}
	return nil
}

func copyCRLBundle(srcPath string, dstPath string) {
	log.V(2).Infof("Copying CRL Bundle from: %s to: %s", srcPath, dstPath)

	dstFiles, err := os.ReadDir(dstPath)
	if err != nil {
		log.V(1).Info(err)
	}
	for _, file := range dstFiles {
		if err := os.Remove(filepath.Join(dstPath, file.Name())); err != nil {
			log.V(1).Info(err)
		}
	}
	srcFiles, err := os.ReadDir(srcPath)
	if err != nil {
		log.V(1).Info(err)
	}
	for _, file := range srcFiles {
		input, err := os.ReadFile(filepath.Join(srcPath, file.Name()))
		if err != nil {
			log.V(1).Info(err)
			continue
		}
		if err = attemptWrite(filepath.Join(dstPath, file.Name()), input, 0644); err != nil {
			log.V(1).Info(err)
			continue
		}
	}
}

func rmSymlink(path string) (string, error) {
	// NOTE: muPath has to be writer-locked when entering this function.
	log.V(2).Infof("Removing sym link: %s", path)
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return "", nil
	}
	// The symbolic link exists. Backup it so it can be restored in case of an emergency.
	old, err := os.Readlink(path)
	if err != nil {
		return "", err
	}
	// Now remove the symbolic link.
	if err := os.Remove(path); err != nil {
		return "", err
	}
	return old, nil
}

func restoreSymlink(oldTarget, link string) error {
	// NOTE: muPath has to be writer-locked when entering this function.
	log.V(2).Infof("Restoring sym link: %s  old: %s", link, oldTarget)
	if oldTarget == "" {
		return nil
	}
	// Check if oldTarget exists before creating the symlink.
	if _, err := os.Stat(oldTarget); os.IsNotExist(err) {
		return fmt.Errorf("oldTarget %q does not exist: %w", oldTarget, err)
	} else if err != nil {
		// Handle other potential errors during os.Stat
		return fmt.Errorf("failed to stat oldTarget %q: %w", oldTarget, err)
	}
	if _, err := rmSymlink(link); err != nil {
		return err
	}
	return os.Symlink(oldTarget, link)
}

func rmFileIfNotPointedToBySymlink(file, link string) error {
	// NOTE: muPath has to be writer-locked when entering this function.
	// Check if link points to a file.
	log.V(2).Infof("Removing file: %s link: %s", file, link)
	if _, err := os.Lstat(link); os.IsNotExist(err) {
		return nil
	}
	// The symbolic link exists. Read the path to the linked file.
	if linked, err := os.Readlink(link); err != nil || file == linked {
		return err
	}
	// Now remove the file.
	return os.Remove(file)
}

func isSymlinkValid(path string) bool {
	// NOTE: muPath has to be writer-locked when entering this function.
	log.V(2).Infof("Validating sym link: %s", path)
	if fi, err := os.Stat(path); os.IsNotExist(err) || fi == nil || !fi.Mode().IsRegular() {
		return false
	}
	return true
}

// symlinkPointsToRotation reports whether link is a symlink that currently
// resolves to a gNSI Certz-rotated artifact and whose target still exists.
// Certz names rotated files with the fixed suffixes produced in Rotate:
// "<profile>_<ver>_<ts>_cert.pem", "..._key.pem" and "ca_..._bundle.pem".
//
// A true result means a rotation is in effect and the link must be preserved
// across a server (re)start so a rotated certificate survives restarts. Any
// other state -- a missing/dangling link, or a link pointing at a
// config-provisioned certificate -- returns false, so the caller (re)links to
// the configured material. This makes a changed config cert take effect on the
// next start and lets stale non-rotation links self-heal, while never clobbering
// an active rotation.
func symlinkPointsToRotation(link string) bool {
	// NOTE: muPath has to be writer-locked when entering this function.
	target, err := os.Readlink(link)
	if err != nil {
		return false // not a symlink, or does not exist
	}
	base := filepath.Base(target)
	if !strings.HasSuffix(base, "_cert.pem") &&
		!strings.HasSuffix(base, "_key.pem") &&
		!strings.HasSuffix(base, "_bundle.pem") {
		return false
	}
	// Preserve only if the rotated target still exists (not dangling).
	if _, err := os.Stat(link); err != nil {
		return false
	}
	return true
}

type profilePaths struct {
	Cert string
	Key  string
	CA   string
	CRL  string
}

func getLinkPaths(cfg *Config, profileID string) profilePaths {
	switch profileID {
	case defaultProfile:
		crlPath := filepath.Join(cfg.CertCRLConfig, crlDefault)
		return profilePaths{
			Cert: cfg.SrvCertLnk,
			Key:  cfg.SrvKeyLnk,
			CA:   cfg.CaCertLnk,
			CRL:  crlPath,
		}
	default:
		baseDir := filepath.Dir(cfg.SrvCertLnk)
		base := filepath.Join(baseDir, certzProfilesDir, profileID)
		return profilePaths{
			Cert: filepath.Join(base, "cert"),
			Key:  filepath.Join(base, "key"),
			CA:   filepath.Join(base, "ca"),
			CRL:  filepath.Join(base, "crl"),
		}
	}
}

func traverseSymlink(path string) string {
	current := path
	for i := 0; i < 255; i++ {
		fi, err := os.Lstat(current)
		if err != nil {
			return current
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			return current
		}
		target, err := os.Readlink(current)
		if err != nil {
			return current
		}
		if !filepath.IsAbs(target) {
			current = filepath.Join(filepath.Dir(current), target)
		} else {
			current = target
		}
	}
	return current
}

// atomicSetSrvCertKeyPair atomically replaces the cert/key pair for the given
// profile. gnxi retargets the telemetry listener; other IDs use
// certz_profiles/<id>/{cert,key} so custom-profile rotation does not swap gNMI certs.
func atomicSetSrvCertKeyPair(cfg *Config, profileID, sCert, sKey string) error {
	// NOTE: muPath has to be writer-locked when entering this function.
	log.V(2).Infof("Attempting to set Cert: %s for profile %s", sCert, profileID)
	if sCert == "" || sKey == "" {
		log.V(1).Infof("Empty cert or key path for profile %s; deleting active symlinks", profileID)
		paths := getLinkPaths(cfg, profileID)
		_, _ = rmSymlink(paths.Cert)
		_, _ = rmSymlink(paths.Key)
		return nil
	}
	paths := getLinkPaths(cfg, profileID)
	certLnk, keyLnk := paths.Cert, paths.Key
	if err := os.MkdirAll(filepath.Dir(certLnk), 0755); err != nil {
		return err
	}

	cert, err := filepath.Abs(sCert)
	if err != nil {
		return err
	}
	key, err := filepath.Abs(sKey)
	if err != nil {
		return err
	}
	oldCert, err := rmSymlink(certLnk)
	if err != nil {
		return err
	}
	oldKey, err := rmSymlink(keyLnk)
	if err != nil {
		_ = restoreSymlink(oldCert, certLnk)
		return err
	}
	if err := os.Symlink(cert, certLnk); err != nil {
		_ = restoreSymlink(oldCert, certLnk)
		_ = restoreSymlink(oldKey, keyLnk)
		return err
	}
	if err := os.Symlink(key, keyLnk); err != nil {
		_ = restoreSymlink(oldCert, certLnk)
		_ = restoreSymlink(oldKey, keyLnk)
		return err
	}
	log.V(2).Infof("Successful Set Cert: %s for profile %s", sCert, profileID)
	return nil
}

// atomicSetSrvCertTPMSigner points the default profile's certificate link at
// sCert and removes its key link, so the listener signs with the TPM key.
func atomicSetSrvCertTPMSigner(cfg *Config, sCert string) error {
	// NOTE: muPath has to be writer-locked when entering this function.
	log.V(2).Infof("Attempting to set TPM-backed Cert: %s", sCert)
	cert, err := filepath.Abs(sCert)
	if err != nil {
		return err
	}
	oldCert, err := rmSymlink(cfg.SrvCertLnk)
	if err != nil {
		return err
	}
	oldKey, err := rmSymlink(cfg.SrvKeyLnk)
	if err != nil {
		_ = restoreSymlink(oldCert, cfg.SrvCertLnk)
		return err
	}
	if err := os.Symlink(cert, cfg.SrvCertLnk); err != nil {
		_ = restoreSymlink(oldCert, cfg.SrvCertLnk)
		_ = restoreSymlink(oldKey, cfg.SrvKeyLnk)
		return err
	}
	log.V(2).Infof("Successful Set TPM-backed Cert: %s", sCert)
	return nil
}

// atomicSetCACert atomically replaces the CA certificate for the given profile.
func atomicSetCACert(cfg *Config, profileID, caCert string) error {
	// NOTE: muPath has to be writer-locked when entering this function.
	log.V(2).Infof("Attempt Set CA: %s for profile %s", caCert, profileID)
	caLnk := getLinkPaths(cfg, profileID).CA
	if err := os.MkdirAll(filepath.Dir(caLnk), 0755); err != nil {
		return err
	}
	if caCert == "" {
		_, _ = rmSymlink(caLnk)
		return nil
	}
	cert, err := filepath.Abs(caCert)
	if err != nil {
		return err
	}
	oldCert, err := rmSymlink(caLnk)
	if err != nil {
		return err
	}
	if err := os.Symlink(cert, caLnk); err != nil {
		_ = restoreSymlink(oldCert, caLnk)
		return err
	}
	log.V(2).Infof("Successful Set CA: %s for profile %s", caCert, profileID)
	return nil
}

func restoreFromFile(link string, file string) string {
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		if path, readErr := os.Readlink(link); readErr == nil {
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				return path
			}
		}
	}

	if _, err := os.Stat(file); os.IsNotExist(err) {
		log.V(0).Infof("cannot find file: %s link: %s", file, link)
		return "unknown"
	}
	return file
}

func attemptWrite(name string, data []byte, perm os.FileMode) error {
	err := os.WriteFile(name, data, perm)
	if err != nil {
		if e := os.Remove(name); e != nil {
			err = fmt.Errorf("Write %s failed: %w; Cleanup failed", name, err)
		}
	}
	return err
}

func (srv *GNSICertzServer) removeEntityFiles(e *genericEntity) {
	if e == nil || srv.config == nil {
		return
	}

	isManagedFilePath := func(path string) bool {
		if path == "" {
			return false
		}
		dir := filepath.Dir(path)
		baseDir := filepath.Dir(srv.config.SrvCertLnk)
		if dir != baseDir && !strings.HasPrefix(dir, filepath.Join(baseDir, certzProfilesDir)+string(os.PathSeparator)) {
			return false
		}
		if path == srv.config.SrvCertFile || path == srv.config.SrvKeyFile || path == srv.config.CaCertFile {
			return false
		}
		pattern := `^(ca_)?[a-zA-Z0-9._-]+_.*_[0-9]+_(cert|key|bundle)\.pem$`
		matched, _ := regexp.MatchString(pattern, filepath.Base(path))
		return matched
	}

	var pathsToRemove []string
	switch e.EType {
	case certType:
		if isManagedFilePath(e.CertPath) {
			pathsToRemove = append(pathsToRemove, e.CertPath)
		}
		if isManagedFilePath(e.KeyPath) {
			pathsToRemove = append(pathsToRemove, e.KeyPath)
		}
	case tbType:
		if isManagedFilePath(e.CertPath) {
			pathsToRemove = append(pathsToRemove, e.CertPath)
		}
	}

	for _, p := range pathsToRemove {
		log.V(2).Infof("Removing profile-managed file: %s", p)
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			log.V(1).Infof("Failed to remove: %s", err)
		}
	}
}

// writeCredentialsMetadataToDB writes the credentials freshness data to the DB.
func writeCredentialsMetadataToDB(tbl, key, fld, val string) error {
	sc, err := common_utils.GetRedisDBClient()
	if err != nil {
		log.V(0).Info(err.Error())
		return fmt.Errorf("REDIS is not available: %v", err)
	}
	defer sc.Close()

	// Write metadata.
	path := common_utils.GetKey([]string{credentialsTbl, tbl})
	if len(key) > 0 {
		path = common_utils.GetKey([]string{path, key})
	}
	dbWriteMutex.Lock()
	err = sc.HSet(context.Background(), path, fld, val).Err()
	dbWriteMutex.Unlock()
	if err != nil {
		log.V(0).Infof("Cannot write credentials metadata to the DB. [path:'%v', fld:'%v', val:'%v']", path, fld, val)
		return err
	}
	log.V(3).Infof("Successfully wrote credentials metadata to the DB. [path:'%v', fld:'%v', val:'%v']", path, fld, val)
	return nil
}

func deleteCredentialsMetadataFromDB(tbl, key string) error {
	sc, err := common_utils.GetRedisDBClient()
	if err != nil {
		log.V(0).Info(err.Error())
		return fmt.Errorf("REDIS is not available: %v", err)
	}
	defer sc.Close()

	path := common_utils.GetKey([]string{credentialsTbl, tbl})
	if len(key) > 0 {
		path = common_utils.GetKey([]string{path, key})
	}
	dbWriteMutex.Lock()
	err = sc.Del(context.Background(), path).Err()
	dbWriteMutex.Unlock()
	if err != nil {
		log.V(0).Infof("Cannot delete credentials metadata from the DB. [path:'%v']", path)
		return err
	}
	log.V(3).Infof("Successfully deleted credentials metadata from the DB. [path:'%v']", path)
	return nil
}

func (srv *GNSICertzServer) sslProfileCheckpoint(action ssc.CredzCheckpointAction, profileID string) {
	if profileID == "" || profileID == defaultProfile {
		return
	}
	sc, err := ssc.NewDbusClientProvider()
	if err != nil {
		log.V(1).Infof("ssl_profile checkpoint %s: dbus client: %v", action, err)
		return
	}
	defer sc.Close()
	if err := sc.SslProfileCheckpoint(action, profileID); err != nil {
		log.V(1).Infof("ssl_profile checkpoint %s for %q failed: %v", action, profileID, err)
	}
}

func (srv *GNSICertzServer) addSslProfile(profileID string) {
	if profileID == "" || profileID == defaultProfile {
		return
	}
	sc, err := ssc.NewDbusClientProvider()
	if err != nil {
		log.V(1).Infof("ssl_profile add_profile: dbus client: %v", err)
		return
	}
	defer sc.Close()
	if err := sc.AddSslProfile(profileID); err != nil {
		log.V(1).Infof("ssl_profile add_profile for %q failed: %v", profileID, err)
	}
}

func (srv *GNSICertzServer) installSslProfile(profileID string) {
	if profileID == "" || profileID == defaultProfile {
		return
	}
	p, ok := srv.profiles[profileID]
	if !ok || p == nil {
		return
	}
	certSrc, keySrc, caSrc := "", "", ""
	if p.ActiveEntities.Cert != nil {
		certSrc = p.ActiveEntities.Cert.CertPath
		keySrc = p.ActiveEntities.Cert.KeyPath
	}
	if p.ActiveEntities.TrustBundle != nil {
		caSrc = p.ActiveEntities.TrustBundle.CertPath
	}
	if certSrc == "" && keySrc == "" && caSrc == "" {
		return
	}
	sc, err := ssc.NewDbusClientProvider()
	if err != nil {
		log.V(1).Infof("ssl_profile install_profile: dbus client: %v", err)
		return
	}
	defer sc.Close()
	if err := sc.InstallSslProfile(profileID, certSrc, keySrc, caSrc); err != nil {
		log.V(1).Infof("ssl_profile install_profile for %q failed: %v", profileID, err)
	}
}

func (srv *GNSICertzServer) deleteSslProfile(profileID string) {
	if profileID == "" || profileID == defaultProfile {
		return
	}
	sc, err := ssc.NewDbusClientProvider()
	if err != nil {
		log.V(1).Infof("ssl_profile delete_profile: dbus client: %v", err)
		return
	}
	defer sc.Close()
	if err := sc.DeleteSslProfile(profileID); err != nil {
		log.V(1).Infof("ssl_profile delete_profile for %q failed: %v", profileID, err)
	}
}

func parseCSRSuite(suite certz.CSRSuite) (int, x509.SignatureAlgorithm) {
	switch suite {
	case certz.CSRSuite_CSRSUITE_X509_KEY_TYPE_RSA_2048_SIGNATURE_ALGORITHM_SHA_2_256:
		return 2048, x509.SHA256WithRSA
	case certz.CSRSuite_CSRSUITE_X509_KEY_TYPE_RSA_2048_SIGNATURE_ALGORITHM_SHA_2_384:
		return 2048, x509.SHA384WithRSA
	case certz.CSRSuite_CSRSUITE_X509_KEY_TYPE_RSA_2048_SIGNATURE_ALGORITHM_SHA_2_512:
		return 2048, x509.SHA512WithRSA
	case certz.CSRSuite_CSRSUITE_X509_KEY_TYPE_RSA_3072_SIGNATURE_ALGORITHM_SHA_2_256:
		return 3072, x509.SHA512WithRSA
	case certz.CSRSuite_CSRSUITE_X509_KEY_TYPE_RSA_3072_SIGNATURE_ALGORITHM_SHA_2_384:
		return 3072, x509.SHA384WithRSA
	case certz.CSRSuite_CSRSUITE_X509_KEY_TYPE_RSA_3072_SIGNATURE_ALGORITHM_SHA_2_512:
		return 3072, x509.SHA512WithRSA
	case certz.CSRSuite_CSRSUITE_X509_KEY_TYPE_RSA_4096_SIGNATURE_ALGORITHM_SHA_2_256:
		return 4096, x509.SHA512WithRSA
	case certz.CSRSuite_CSRSUITE_X509_KEY_TYPE_RSA_4096_SIGNATURE_ALGORITHM_SHA_2_384:
		return 4096, x509.SHA384WithRSA
	case certz.CSRSuite_CSRSUITE_X509_KEY_TYPE_RSA_4096_SIGNATURE_ALGORITHM_SHA_2_512:
		return 4096, x509.SHA512WithRSA
	case certz.CSRSuite_CSRSUITE_X509_KEY_TYPE_ECDSA_PRIME256V1_SIGNATURE_ALGORITHM_SHA_2_256:
		return 256, x509.ECDSAWithSHA256
	case certz.CSRSuite_CSRSUITE_X509_KEY_TYPE_ECDSA_PRIME256V1_SIGNATURE_ALGORITHM_SHA_2_384:
		return 256, x509.ECDSAWithSHA384
	case certz.CSRSuite_CSRSUITE_X509_KEY_TYPE_ECDSA_PRIME256V1_SIGNATURE_ALGORITHM_SHA_2_512:
		return 256, x509.ECDSAWithSHA512
	case certz.CSRSuite_CSRSUITE_X509_KEY_TYPE_ECDSA_SECP384R1_SIGNATURE_ALGORITHM_SHA_2_256:
		return 384, x509.ECDSAWithSHA256
	case certz.CSRSuite_CSRSUITE_X509_KEY_TYPE_ECDSA_SECP384R1_SIGNATURE_ALGORITHM_SHA_2_384:
		return 384, x509.ECDSAWithSHA384
	case certz.CSRSuite_CSRSUITE_X509_KEY_TYPE_ECDSA_SECP384R1_SIGNATURE_ALGORITHM_SHA_2_512:
		return 384, x509.ECDSAWithSHA512
	case certz.CSRSuite_CSRSUITE_X509_KEY_TYPE_ECDSA_SECP521R1_SIGNATURE_ALGORITHM_SHA_2_256:
		return 521, x509.ECDSAWithSHA256
	case certz.CSRSuite_CSRSUITE_X509_KEY_TYPE_ECDSA_SECP521R1_SIGNATURE_ALGORITHM_SHA_2_384:
		return 521, x509.ECDSAWithSHA384
	case certz.CSRSuite_CSRSUITE_X509_KEY_TYPE_ECDSA_SECP521R1_SIGNATURE_ALGORITHM_SHA_2_512:
		return 521, x509.ECDSAWithSHA512
	case certz.CSRSuite_CSRSUITE_X509_KEY_TYPE_EDDSA_ED25519:
		return 256, x509.PureEd25519
	case certz.CSRSuite_CSRSUITE_CIPHER_UNSPECIFIED:
		fallthrough
	default:
		return 0, x509.UnknownSignatureAlgorithm
	}
}
