package gnmi

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"sync"
	"time"

	log "github.com/golang/glog"
	"github.com/redis/go-redis/v9"
	sdcfg "github.com/sonic-net/sonic-gnmi/sonic_db_config"
)

// The gRPC listener presents the gNSI Certz SSL profile named by the
// OpenConfig leaf /system/grpc-servers/grpc-server/config/certificate-id.
// translib stores that leaf in CONFIG_DB as GNMI|gnmi:certificate_id, which
// makes the binding survive a telemetry restart and keeps the write path
// vendor-neutral. An unset id means the default (gnxi) profile, so a device
// that never touches certificate-id behaves exactly as before.
const (
	gnmiCfgTable   = "GNMI"
	gnmiCfgKey     = "gnmi"
	certIdField    = "certificate_id"
	configDbName   = "CONFIG_DB"
	configDbKeySep = "|"

	// servingChoiceTTL bounds how stale the chosen profile may be. Only the
	// choice is cached, never the credentials: the cached paths are the
	// profile's symlinks, which the handshake still follows to whatever they
	// currently target, so a Certz rotation is picked up immediately.
	servingChoiceTTL = 2 * time.Second
)

var (
	servingMu sync.Mutex
	// servingPaths starts on the default profile so a listener that cannot
	// reach CONFIG_DB still has usable material to present.
	servingID      = defaultProfile
	servingPaths   profilePaths
	servingHavePin bool
	servingExpires time.Time
)

// configDbClient dials CONFIG_DB. The caller owns the returned client.
func configDbClient() (*redis.Client, error) {
	ns, err := sdcfg.GetDbDefaultNamespace()
	if err != nil {
		return nil, err
	}
	addr, err := sdcfg.GetDbTcpAddr(configDbName, ns)
	if err != nil {
		return nil, err
	}
	id, err := sdcfg.GetDbId(configDbName, ns)
	if err != nil {
		return nil, err
	}
	return redis.NewClient(&redis.Options{
		Network: "tcp",
		Addr:    addr,
		DB:      id,
	}), nil
}

func readBoundProfileID() (string, error) {
	c, err := configDbClient()
	if err != nil {
		return "", err
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	id, err := c.HGet(ctx, gnmiCfgTable+configDbKeySep+gnmiCfgKey, certIdField).Result()
	if err == redis.Nil {
		return "", nil
	}
	return id, err
}

// unbindProfile drops the certificate-id binding when it names profileID, so
// deleting a profile leaves the listener explicitly back on the default rather
// than pointing at material that no longer exists.
func unbindProfile(profileID string) {
	if profileID == "" || profileID == defaultProfile {
		return
	}
	c, err := configDbClient()
	if err != nil {
		log.V(1).Infof("certificate-id: cannot unbind %q: %v", profileID, err)
		return
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	key := gnmiCfgTable + configDbKeySep + gnmiCfgKey
	switch current, err := c.HGet(ctx, key, certIdField).Result(); {
	case err == redis.Nil:
		return
	case err != nil:
		log.V(1).Infof("certificate-id: cannot unbind %q: %v", profileID, err)
		return
	case current != profileID:
		return
	}
	if err := c.HDel(ctx, key, certIdField).Err(); err != nil {
		log.V(1).Infof("certificate-id: cannot unbind %q: %v", profileID, err)
		return
	}
	log.V(1).Infof("certificate-id: profile %q deleted, listener back on %q", profileID, defaultProfile)

	servingMu.Lock()
	servingExpires = time.Time{}
	servingMu.Unlock()
}

// servingProfilePaths returns the links the listener presents for a new
// connection: the bound profile's when certificate-id names one that is fully
// usable, the default profile's otherwise.
//
// The choice is made once for all of a profile's material rather than per
// artifact. That is what keeps the identity certificate and the CA used to
// verify clients from ever coming from different profiles, and it means a
// typo or a half-rotated profile cannot cost operators access to the device.
//
// advancedtls asks for the identity certificate and for the trust roots in two
// separate callbacks, so a rebind landing between them can still fail the one
// handshake that straddles it; the client simply reconnects. Caching the choice
// is what keeps that window to the rebind itself instead of every connection.
//
// NOTE: muPath has to be read-locked when entering this function.
func servingProfilePaths(cfg *Config) profilePaths {
	servingMu.Lock()
	defer servingMu.Unlock()

	if servingHavePin && time.Now().Before(servingExpires) {
		return servingPaths
	}

	def := getLinkPaths(cfg, defaultProfile)
	id, err := readBoundProfileID()
	switch {
	case err != nil && !servingHavePin:
		log.V(1).Infof("certificate-id: cannot read %s|%s: %v", gnmiCfgTable, gnmiCfgKey, err)
		return def
	case err != nil:
		// A transient CONFIG_DB outage must not flap the binding, so keep the
		// profile chosen last. It is still re-checked below: the profile may
		// have been deleted while Redis was unreachable, and falling back to
		// the default beats failing every handshake until Redis returns.
		log.V(1).Infof("certificate-id: cannot read %s|%s: %v", gnmiCfgTable, gnmiCfgKey, err)
		id = servingID
	case id == "":
		id = defaultProfile
	}

	paths := def
	if id != defaultProfile {
		if bound, uerr := usableProfile(cfg, id); uerr != nil {
			log.V(0).Infof("certificate-id %q is not usable (%v); serving %q instead", id, uerr, defaultProfile)
		} else {
			paths = bound
		}
	}
	if id != servingID {
		log.V(1).Infof("certificate-id: listener now bound to profile %q", id)
	}
	servingID, servingPaths, servingHavePin = id, paths, true
	servingExpires = time.Now().Add(servingChoiceTTL)
	return paths
}

// usableProfile returns a profile's links only if every artifact the listener
// needs actually loads. Checking them together is what makes the fallback
// all-or-nothing.
func usableProfile(cfg *Config, id string) (profilePaths, error) {
	p := getLinkPaths(cfg, id)
	if _, err := loadServingKeyPair(cfg, p.Cert, p.Key); err != nil {
		return profilePaths{}, err
	}
	if cfg.CaCertFile != "" {
		if _, err := readCertPool(p.CA); err != nil {
			return profilePaths{}, err
		}
	}
	return p, nil
}

func readCertPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read CA certificate: %s", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("failed to append CA certificate from %s", path)
	}
	return pool, nil
}
