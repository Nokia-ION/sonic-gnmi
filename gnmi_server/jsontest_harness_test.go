package gnmi

// jsontest_harness_test.go: Off-box harness that drives the json based GNMI
// component test library (github.com/sonic-net/sonic-gnmi/jsontest) against a
// gNMI server backed by a local (virtual) Redis instance.
//
// Each json file under testdata/json_tests/getset describes a sequence of gNMI
// operations (get/replace/update/delete) plus optional validators. Before every
// file the relevant DBs are flushed and re-seeded from the *_db.txt fixtures so
// tests are order-independent.
//
// Run off-box (example):
//   JSON_TGT='port_ethernet0.json' \
//     go test -mod=vendor -run TestGnmiJsonGetSet -v ./gnmi_server/...

import (
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Azure/sonic-mgmt-common/translib/db"
	"github.com/Azure/sonic-mgmt-common/translib/transformer"
	jtest "github.com/sonic-net/sonic-gnmi/jsontest"
	sdcfg "github.com/sonic-net/sonic-gnmi/sonic_db_config"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Port used by the json test harness server. Kept distinct from the other
// server_test.go tests so they do not collide when run together.
const jsonTestPort int64 = 8090

// onSonicSwitch reports whether the tests are running on a live SONiC switch.
// When true, the DBs are assumed to hold real data and are not re-seeded.
func jsonOnSonicSwitch() bool {
	fileInfo, err := os.Stat("/etc/sonic/sonic_version.yml")
	if err != nil {
		return false
	}
	return fileInfo.Size() != 0
}

// prepareJsonDbUtil loads json fixture files into the given db under an optional key.
func prepareJsonDbUtil(t *testing.T, dbName string, key string, files ...string) {
	for _, f := range files {
		if err := jtest.LoadFileToDB(dbName, key, f); err != nil {
			t.Fatalf("Failed to load config %s into %s: %v", f, dbName, err)
		}
	}
}

// jsonTestDbInit flushes and re-seeds the DBs used by the json test cases.
// It is a no-op on a live switch.
func jsonTestDbInit(t *testing.T) {
	if jsonOnSonicSwitch() {
		return
	}

	dbInits := []struct {
		name string
		file string
	}{
		{"CONFIG_DB", "../testdata/json_tests/config_db.txt"},
	}

	ns, _ := sdcfg.GetDbDefaultNamespace()
	for _, dbI := range dbInits {
		// Only seed fixtures that are present so the harness stays usable
		// even when only a subset of DB snapshots is provided.
		if _, err := os.Stat(dbI.file); err != nil {
			continue
		}
		dbId, err := sdcfg.GetDbId(dbI.name, ns)
		if err != nil {
			t.Fatalf("failed to get DB Id for %s, %v", dbI.name, err)
		}
		rclient := getRedisClientN(t, dbId, ns)
		defer db.CloseRedisClient(rclient)
		rclient.FlushDB(context.Background())
		prepareJsonDbUtil(t, dbI.name, "", dbI.file)
	}
	transformer.TestingQosClearState()
}

// TestGnmiJsonGetSet runs every json get/set test file under
// testdata/json_tests/getset. Set the JSON_TGT env var to a glob (e.g.
// "port_ethernet0.json") to run a subset.
func TestGnmiJsonGetSet(t *testing.T) {
	var hook jtest.JSONFilter

	s := createServer(t, jsonTestPort)
	s.config.EnableTranslation = true
	go runServer(t, s)
	defer s.Stop()

	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	opts := []grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))}

	targetAddr := fmt.Sprintf("127.0.0.1:%d", jsonTestPort)
	conn, err := grpc.Dial(targetAddr, opts...)
	if err != nil {
		t.Fatalf("Dialing to %q failed: %v", targetAddr, err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Second)
	ctx = context.WithValue(ctx, jtest.CtxIDGChannel, conn)
	defer cancel()

	fileFilter := os.Getenv("JSON_TGT")
	if fileFilter == "" {
		fileFilter = "*.json"
	}

	files, err := filepath.Glob("../testdata/json_tests/getset/" + fileFilter)
	if err != nil {
		t.Fatalf("Error globbing test files: %v", err)
	}
	if len(files) == 0 {
		t.Skipf("No json test files matched ../testdata/json_tests/getset/%s", fileFilter)
	}

	var tds []jtest.UnitTest
	for _, f := range files {
		tst, err := jtest.UnitTestFromFile(t, ctx, f, hook)
		if err != nil {
			t.Fatalf("File: %s: %v", f, err)
		}
		tds = append(tds, tst)
	}

	for _, td := range tds {
		jsonTestDbInit(t) // Reset DB contents before each file.
		jtest.RunTest(t, ctx, &td)
		time.Sleep(250 * time.Millisecond) // Allow the change to register.
	}
}
