package jtest

// jsontest.go: A json based GNMI component test library

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Azure/sonic-mgmt-common/translib/ocbinds"
	pathutil "github.com/Azure/sonic-mgmt-common/translib/path"
	"github.com/golang/protobuf/proto"
	xpathutl "github.com/google/gnxi/utils/xpath"
	pb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/openconfig/ygot/ygot"
	"github.com/openconfig/ygot/ytypes"
	transutil "github.com/sonic-net/sonic-gnmi/transl_utils"
	"github.com/xeipuuv/gojsonschema"

	"golang.org/x/net/context"
)

const (
	PStrSchema  string = "schema"
	PStrXpath   string = "xpath"
	PStrCheckSR string = "syncResponse"
)

// sub-operations
const (
	Poll           op_t = iota + 100 // Poll request for POLL Subscription
	DBHSet                           // Redis HSet Operation
	DBHDel                           // Redis HDel Operation
	DBLoad                           // Load DB from files
	DBReset                          // Reset DB to initial state
	Validate                         // Validation point
	DBHGetValidate                   // Redis HGet Operation and Validate
)

// Defines SubOperation Interface
type SubOperation interface {
	Oper() op_t
	Desc() string
	Load(ctx context.Context, subOperJSON map[string]interface{}) error
	Execute(t *testing.T, ctx context.Context)
}

// Defines Base SubOperation
type baseSubOper struct {
	parent Operation
	oper   op_t
	desc   string
}

// DB SubOperation
type dbSubOper struct {
	baseSubOper
	db    string
	value string
}

// GNMI SubOperation
type gnmiSubOper struct {
	baseSubOper
	req proto.Message
}

// Validator
type validator struct {
	optional      bool
	consume       bool                    // consume the matched update or not
	schema        gojsonschema.JSONLoader // validator json schema
	path          *pb.Path
	checkSyncResp bool // Need to check syncResponse
	timestamp     int64
}

// Validation Context
type validateContext struct {
	vso         *validateSubOper
	pvHitCntMap map[string]int         // record path validator hit counts
	nonHitPVs   int                    // number of non-optional path validators not hit
	finalUpd    ygot.ValidatedGoStruct // combined update from all non-consumed updates
	syncRcvd    bool                   // Received sync response
	finalJSON   string
	updateCount map[string]int
}

// Validate SubOperation
type validateSubOper struct {
	baseSubOper
	timeout               time.Duration         // timeout in million seconds
	allowDuplicateUpdates bool                  // allow duplicate updates in gNMI Subscription
	finalValidator        *validator            // for validating the finalUpd
	pathValidators        map[string]*validator // path validators
}

var ygSchema *ytypes.Schema

func init() {
	var err error
	if ygSchema, err = ocbinds.GetSchema(); err != nil {
		panic("Error in getting the schema: " + err.Error())
	}
}

// Creates a SubOperation from JSON.
func NewSubOperation(ctx context.Context, parentOp Operation, subOperJSON map[string]interface{}) (SubOperation, error) {
	val, ok := subOperJSON["oper"]
	if !ok {
		return nil, fmt.Errorf("No oper specified.")
	}

	op := val.(string)
	desc := op
	if val, ok = subOperJSON["title"]; ok {
		desc = val.(string)
	}

	var subOper SubOperation
	switch op {
	case "poll":
		subOper = &gnmiSubOper{baseSubOper: baseSubOper{oper: Poll, desc: desc, parent: parentOp}}
	case "dbHGetValidate":
		subOper = &dbSubOper{baseSubOper: baseSubOper{oper: DBHGetValidate, desc: desc, parent: parentOp}}
	case "dbHSet":
		subOper = &dbSubOper{baseSubOper: baseSubOper{oper: DBHSet, desc: desc, parent: parentOp}}
	case "dbHDel":
		subOper = &dbSubOper{baseSubOper: baseSubOper{oper: DBHDel, desc: desc, parent: parentOp}}
	case "dbLoad":
		subOper = &dbSubOper{baseSubOper: baseSubOper{oper: DBLoad, desc: desc, parent: parentOp}}
	case "dbReset":
		subOper = &dbSubOper{baseSubOper: baseSubOper{oper: DBReset, desc: desc, parent: parentOp}}
	case "validate":
		subOper = &validateSubOper{baseSubOper: baseSubOper{oper: Validate, desc: desc, parent: parentOp}, pathValidators: map[string]*validator{}}
	default:
		return nil, fmt.Errorf("Unknown sub-operation:%v", op)
	}

	if err := subOper.Load(ctx, subOperJSON); err != nil {
		return nil, fmt.Errorf("Failed to parse sub-operation:%v", err)
	}

	return subOper, nil
}

// Methods for baseSubOper
func (bso *baseSubOper) Oper() op_t {
	return bso.oper
}

func (bso *baseSubOper) Desc() string {
	return bso.desc
}

// Methods for dbSubOper
func (dso *dbSubOper) Load(ctx context.Context, subOperJSON map[string]interface{}) error {
	val, ok := subOperJSON["db"]
	if !ok {
		return fmt.Errorf("Error parsing DB operation %s: No db specified.", dso.Desc())
	}
	dso.db = val.(string)

	if dso.baseSubOper.Oper() == DBReset {
		return nil
	}

	if val, ok = subOperJSON["value"]; !ok {
		return fmt.Errorf("Error parsing DB operation %s: No value specified.", dso.Desc())
	}

	if dso.baseSubOper.Oper() == DBLoad {
		// Get file content
		jv, err := ioutil.ReadFile(val.(string))
		if err != nil {
			return fmt.Errorf("Error readfile %s: No value specified.", val.(string))
		}
		dso.value = string(jv)
	} else {
		if jv, err := json.Marshal(val); err != nil {
			return fmt.Errorf("Invalid JSON DB value:", dso.Desc())
		} else {
			dso.value = string(jv)
		}
	}

	return nil
}

func (dso *dbSubOper) Execute(t *testing.T, ctx context.Context) {
	var err error
	switch dso.Oper() {
	case DBHDel:
		err = RemoveConfigFromDB(dso.db, "", dso.value)
	case DBHGetValidate:
		err = ReadConfigFromDBandValidate(dso.db, "", dso.value)
	case DBLoad, DBHSet:
		err = LoadConfigToDB(dso.db, "", dso.value)
	default:
		err = fmt.Errorf("Invalid db operation.")
	}

	if err != nil {
		t.Fatalf("DBSubOper %v error: %v", dso.Desc(), err)
	}
}

// Methods for gnmiSubOper.
func (gso *gnmiSubOper) Load(ctx context.Context, subOperJSON map[string]interface{}) error {
	switch gso.Oper() {
	case Poll:
		gso.req = &pb.SubscribeRequest{Request: &pb.SubscribeRequest_Poll{Poll: &pb.Poll{}}}
	default:
		return fmt.Errorf("Unsupported gnmi suboper:" + gso.Desc())
	}

	return nil
}

func (gso *gnmiSubOper) Execute(t *testing.T, ctx context.Context) {
	subSess := ctx.Value(CtxIDSubscribeSess).(*subscribeSession)
	if subSess == nil {
		t.Fatal("No subscribe session:" + gso.Desc())
	}

	switch gso.Oper() {
	case Poll:
		if err := subSess.subClient.Send(gso.req.(*pb.SubscribeRequest)); err != nil {
			t.Fatalf("Failed to send poll request:%v", err)
		}
	default:
		t.Fatal("Unsupported gnmi suboper:" + gso.Desc())
	}
}

// Methods for validateContext.
func removeOpenconfigPrefix(xpath string) string {
	if strings.HasPrefix(xpath, "/openconfig") {
		return string(xpath[11:])
	}
	return xpath
}

func getFullPath(prefix, path *pb.Path) *pb.Path {
	if prefix == nil {
		return path
	}
	// Prefers prefix.Origin
	fullPath := &pb.Path{Origin: prefix.Origin}
	if len(fullPath.Origin) == 0 {
		fullPath.Origin = path.Origin
	}
	if path.GetElement() != nil {
		fullPath.Element = append(prefix.GetElement(), path.GetElement()...)
	}
	if path.GetElem() != nil {
		fullPath.Elem = append(prefix.GetElem(), path.GetElem()...)
	}
	return fullPath
}

func getParentPath(path *pb.Path) *pb.Path {
	n := len(path.GetElem())
	switch n {
	case 0, 1:
		return &pb.Path{Origin: path.Origin}
	default:
		return &pb.Path{Origin: path.Origin, Elem: path.Elem[:n-1]}
	}
}

// Returns true if path is empty.
func isEmptyPath(path *pb.Path) bool {
	n := len(path.GetElem())
	switch n {
	case 0:
		return true
	default:
		return false
	}
}

// Merges update upd into vctx.finalUpd.
func (vctx *validateContext) mergeUpdate(prefix *pb.Path, upd *pb.Update) error {
	updPath := getFullPath(prefix, upd.GetPath())
	tv := upd.GetVal()
	if tv.GetJsonIetfVal() == nil {
		// Proto Encoding
		if err := ytypes.SetNode(ygSchema.RootSchema(), vctx.finalUpd, updPath, tv, &ytypes.InitMissingElements{}); err != nil {
			fmt.Printf("Merge PROTO value %v, failed:%v\n", updPath, err)
			return err
		}
	} else {
		// JSON_IETF encoding
		jv := getUpdateJSONVal(prefix, upd)
		parentPath := getParentPath(updPath)
		ygNodes, _, err := ytypes.GetOrCreateNode(ygSchema.RootSchema(), vctx.finalUpd, parentPath)
		if err != nil {
			return fmt.Errorf("Failed to create node:%v", err)
		}

		err = ocbinds.Unmarshal([]byte(jv), ygNodes.(ygot.GoStruct))
		if err != nil {
			fmt.Printf("Merge failed:%v\n", err)
			return err
		}
	}

	return nil

}

// Returns true if vctx validation is successful.
func (vctx *validateContext) succeed(t *testing.T, logIfFail bool) bool {
	if vctx.nonHitPVs > 0 {
		return false
	}

	vso := vctx.vso
	if vso.finalValidator == nil {
		return true
	}

	// Check if syncResponse is needed.
	if vso.finalValidator.checkSyncResp && !vctx.syncRcvd {
		return false
	}

	if !vso.allowDuplicateUpdates {
		okay := true
		for path, count := range vctx.updateCount {
			if count > 1 {
				okay = false
				t.Logf("Duplicate update (%d): %s\n", count, path)
			}
		}
		if !okay {
			return false
		}
	}
	if vso.finalValidator.schema == nil || vso.finalValidator.path == nil {
		return true
	}

	parentPath := getParentPath(vso.finalValidator.path)
	vldtrNode, _, err := ytypes.GetOrCreateNode(ygSchema.RootSchema(), vctx.finalUpd, parentPath)
	if err != nil {
		fmt.Println("Error getting node for xpath[", vso.finalValidator.path, "]:", err)
		return false
	}

	vctx.finalJSON, err = ygot.EmitJSON(vldtrNode.(ygot.ValidatedGoStruct), &ygot.EmitJSONConfig{
		Format:         ygot.RFC7951,
		Indent:         "  ",
		SkipValidation: true,
		RFC7951Config: &ygot.RFC7951JSONConfig{
			AppendModuleName: true,
		},
	})

	if err != nil {
		// Ignore the error. Use validator to fail the test.
		t.Log("Failed to generate JSON:", err)
	}

	docLoader := gojsonschema.NewStringLoader(vctx.finalJSON)
	result, err := gojsonschema.Validate(vso.finalValidator.schema, docLoader)
	if err != nil {
		t.Logf("Error validating response JSON: %v\n", err)
		if logIfFail {
			t.Log(vctx.finalJSON)
		}
		return false
	}
	if !result.Valid() {
		t.Log(vso.Desc(), ": Final validation not done yet --- \n", result.Errors())
		if logIfFail {
			t.Log(vctx.finalJSON)
		}
		return false
	}
	return true
}

// Deletes node from the finalUpd
func (vctx *validateContext) mergeDelete(prefix *pb.Path, path *pb.Path) error {
	if err := ytypes.DeleteNode(ygSchema.RootSchema(), vctx.finalUpd, getFullPath(prefix, path)); err != nil {
		return fmt.Errorf("Failed to delete node:%v", err)
	}

	return nil
}

// Creates a new validation context.
func newValidateContext(vso *validateSubOper) *validateContext {
	vldCtx := validateContext{vso: vso, finalUpd: &ocbinds.Device{}}
	vldCtx.pvHitCntMap = make(map[string]int)
	for xpath, vldtr := range vso.pathValidators {
		vldCtx.pvHitCntMap[xpath] = 0
		if !vldtr.optional {
			vldCtx.nonHitPVs++
		}
	}
	vldCtx.updateCount = make(map[string]int)
	return &vldCtx
}

// Methods for validateSubOper
func (vso *validateSubOper) Load(ctx context.Context, subOperJSON map[string]interface{}) error {
	val, ok := subOperJSON["timeout"]
	if !ok {
		return fmt.Errorf("No timeout defined for sub-oper:" + vso.Desc())
	}
	if timeout, err := val.(json.Number).Int64(); err != nil {
		return fmt.Errorf("Invalid timeout %v for sub-oper:", val.(json.Number).String(), vso.Desc())
	} else {
		vso.timeout = time.Duration(timeout) * time.Millisecond
	}

	// Loads pathValidators.
	if pathVldtrs, ok := subOperJSON["pathValidators"]; ok {
		for _, pv := range pathVldtrs.([]interface{}) {
			var vldtr validator
			var xpath string
			var err error
			pvMap := pv.(map[string]interface{})
			if val, ok := pvMap[PStrXpath]; ok {
				xpath = removeOpenconfigPrefix(val.(string))
				if vldtr.path, err = xpathutl.ToGNMIPath(xpath); err != nil {
					return fmt.Errorf("Invalid xpath[%v]:%v", xpath, err)
				}
			}
			if val, ok := pvMap["optional"]; ok {
				vldtr.optional = val.(bool)
			}
			if val, ok := pvMap["consume"]; ok {
				vldtr.consume = val.(bool)
			}
			if val, ok := pvMap["timestamp"]; ok {
				if ts, err := strconv.ParseInt(val.(string), 10, 64); err == nil {
					vldtr.timestamp = ts
				}
			}
			if val, ok := pvMap[PStrSchema]; ok {
				sMap := val.(map[string]interface{})
				sMap[SchemaIDGDef] = subOperJSON[SchemaIDGDef]
				vldtr.schema = gojsonschema.NewGoLoader(sMap)
			}
			if len(xpath) == 0 {
				return fmt.Errorf("Invalid validator: no xpath defined!")
			}
			vso.pathValidators[xpath] = &vldtr
		}
	}

	// Loads finalValidator
	if val, ok = subOperJSON["finalValidator"]; !ok {
		return nil
	}

	var err error
	vso.finalValidator = &validator{}

	fvMap, ok := val.(map[string]interface{})
	if !ok {
		return fmt.Errorf("Invalid finalValidator: %v", val)
	}

	// xpath is needed for finalValidator.
	if val, ok = fvMap[PStrCheckSR]; ok {
		if vso.finalValidator.checkSyncResp, ok = val.(bool); !ok {
			return fmt.Errorf("Invalid %s value (%v), must be true or false.", PStrCheckSR, val)
		}
	}

	// xpath is needed for finalValidator.
	if val, ok = fvMap[PStrXpath]; !ok {
		if !vso.finalValidator.checkSyncResp {
			return fmt.Errorf("No xpath specified for finalValidator")
		}
	} else {
		xpath := removeOpenconfigPrefix(val.(string))
		if vso.finalValidator.path, err = xpathutl.ToGNMIPath(xpath); err != nil {
			return fmt.Errorf("Invalid finalValidator path: %v", xpath)
		}
	}

	// schema is needed for finalValidator
	if val, ok = fvMap[PStrSchema]; !ok {
		if !vso.finalValidator.checkSyncResp {
			return fmt.Errorf("No schema defined for finalValidator")
		}
	} else {
		if fvMap, ok = val.(map[string]interface{}); !ok {
			return fmt.Errorf("Invalid schema:%v", val)
		}
		fvMap[SchemaIDGDef] = subOperJSON[SchemaIDGDef]
		vso.finalValidator.schema = gojsonschema.NewGoLoader(fvMap)
	}

	vso.allowDuplicateUpdates = true
	if _, ok = subOperJSON["allowDuplicateUpdates"]; ok {
		vso.allowDuplicateUpdates = subOperJSON["allowDuplicateUpdates"].(bool)
	}

	return nil
}

func (vso *validateSubOper) validate(ctx *validateContext, ntfy *pb.Notification) error {
	// Always process delete first.
	prefix := ntfy.GetPrefix()

	for _, delPath := range ntfy.GetDelete() {
		xpath, err := transutil.ConvertToURI(prefix, delPath, &pathutil.AddWildcardKeys{})
		if err != nil {
			return fmt.Errorf("Invalid update path.")
		}

		if pvldtr, ok := vso.pathValidators[xpath]; !ok {
			fmt.Println("No path validator found for Del xpath:", xpath)
			ctx.mergeDelete(prefix, delPath)
		} else {
			if pvldtr.schema != nil {
				continue
			}
			// Updates hit count map.
			ctx.pvHitCntMap[xpath]++
			if ctx.pvHitCntMap[xpath] == 1 && !pvldtr.optional && ctx.nonHitPVs > 0 {
				ctx.nonHitPVs--
			}
			// Merges to finalUpd if not consumed.
			if !pvldtr.consume {
				ctx.mergeDelete(prefix, delPath)
			}
		}
	}

	for _, upd := range ntfy.GetUpdate() {
		if isEmptyPath(upd.GetPath()) {
			continue
		}
		fmt.Printf("Processing upd:%.200s\n", proto.CompactTextString(upd))
		xpath, err := transutil.ConvertToURI(prefix, upd.GetPath(), &pathutil.AddWildcardKeys{})
		if err != nil {
			return fmt.Errorf("Invalid update path.")
		}
		if !vso.allowDuplicateUpdates {
			// Keep track of the number of updates for each path if we require all udpates to be unique.
			if _, ok := ctx.updateCount[xpath]; ok {
				fmt.Printf("Duplicate update for %s\n", xpath)
				ctx.updateCount[xpath]++
			} else {
				ctx.updateCount[xpath] = 1
			}
		}
		if pvldtr, ok := vso.pathValidators[xpath]; !ok {
			// No path validator for this path, merge this response to the final JSON
			fmt.Println("No path validator found for Upd xpath:", xpath)
			ctx.mergeUpdate(prefix, upd)
			continue
		} else {
			// No schema path validator is for delete notification.
			if pvldtr.schema == nil {
				continue
			}
			if pvldtr.timestamp != 0 && ntfy.Timestamp != pvldtr.timestamp {
				fmt.Printf("Path validation not ok, timestamp: want %v, got %v\n", pvldtr.timestamp, ntfy.Timestamp)
				continue
			}
			if err := validateUpdate(ntfy.GetPrefix(), upd, pvldtr.schema); err != nil {
				fmt.Printf("Path validation not ok (%v):%v", xpath, err)
				continue
			}
			// Updates hit count map.
			ctx.pvHitCntMap[xpath]++
			if ctx.pvHitCntMap[xpath] == 1 && !pvldtr.optional && ctx.nonHitPVs > 0 {
				ctx.nonHitPVs--
			}
			fmt.Printf("Update validated for %s, hitcount:%d, nhp_count:%d\n", xpath, ctx.pvHitCntMap[xpath], ctx.nonHitPVs)
			// Merges to finalUpd if not consumed.
			if !pvldtr.consume {
				ctx.mergeUpdate(prefix, upd)
			}
		}
	}

	return nil
}

func (vso *validateSubOper) Execute(t *testing.T, ctx context.Context) {
	subSess := ctx.Value(CtxIDSubscribeSess).(*subscribeSession)
	if subSess == nil {
		t.Fatal("No subscribe session:" + vso.Desc())
	}

	// Create a new ctx with timeout
	execCtx, cancel := context.WithTimeout(ctx, vso.timeout)
	defer cancel()

	vldCtx := newValidateContext(vso)

	for {
		select {
		case <-execCtx.Done():
			if !vldCtx.succeed(t, true) {
				t.Fatal("validation timed out.")
			}
			return

		case msg, ok := <-subSess.notification():
			if !ok {
				// Response channel is closed.
				if !vldCtx.succeed(t, true) {
					t.Fatal("Subscribe channel closed.")
				}
				return
			}
			if err, ok := msg.(error); ok {
				t.Fatal(err)
			}
			if _, ok := msg.(bool); ok {
				// syncResponse
				fmt.Println("Received sync response.")
				vldCtx.syncRcvd = true
				if vldCtx.succeed(t, true) {
					return
				}
				if vso.finalValidator != nil && vso.finalValidator.checkSyncResp {
					t.Fatal("validation failed (upon SyncResponse). Final JSON:\n" + vldCtx.finalJSON)
				}
				continue
			}
			if ntfy, ok := msg.(*pb.Notification); !ok {
				t.Fatal("Invalid response.")
			} else if err := vso.validate(vldCtx, ntfy); err != nil {
				t.Fatal(err)
			}

			if vldCtx.succeed(t, false) {
				return
			}
		}
	}
}
