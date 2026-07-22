package jtest

// jsontest.go: A json based GNMI component test library

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Azure/sonic-mgmt-common/translib/ocbinds"
	"github.com/golang/protobuf/proto"
	"github.com/google/gnxi/utils/xpath"
	pb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/openconfig/gnmi/value"
	"github.com/openconfig/ygot/ygot"
	"github.com/openconfig/ygot/ytypes"
	"github.com/xeipuuv/gojsonschema"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type op_t int

// Main Operations
const (
	Delete    op_t = 1
	Replace   op_t = 2
	Update    op_t = 3
	Get       op_t = 4
	Subscribe op_t = 5
)

// Defines Operation Interface.
type Operation interface {
	Oper() op_t
	Desc() string
	Load(ctx context.Context, subOperJSON map[string]interface{}) error
	Execute(t *testing.T, ctx context.Context)
}

// Defines Base Operation struct
type baseOperation struct {
	pathTarget    string
	origin        string
	textPbPath    string
	wantRetCode   codes.Code
	wantRespVal   interface{}
	getDataType   pb.GetRequest_DataType
	attributeData string
	operation     op_t
	desc          string        // description of this operation
	pbReq         proto.Message // GNMI Request from text protobuf
	schema        gojsonschema.JSONLoader
	subOpers      []SubOperation
}

type getOperation struct {
	baseOperation
}

type setOperation struct {
	baseOperation
}

type subscribeOperation struct {
	baseOperation
}

// Subscribe Session (across one subscribe operation)
type subscribeSession struct {
	subClient pb.GNMI_SubscribeClient // gNMI SubscribeClient
	chNtfy    chan interface{}        // Notification channel between Recv routine and operation
	done      atomic.Bool             // Indicates session is finished.
}

// Create a Operation
func NewOperation(ctx context.Context, operJSON map[string]interface{}) (Operation, error) {
	var oper Operation

	switch operJSON["operation"].(string) {
	case "replace":
		oper = &setOperation{baseOperation: baseOperation{operation: Replace}}
	case "update":
		oper = &setOperation{baseOperation: baseOperation{operation: Update}}
	case "delete":
		oper = &setOperation{baseOperation: baseOperation{operation: Delete}}
	case "get":
		oper = &getOperation{baseOperation: baseOperation{operation: Get}}
	case "subscribe":
		oper = &subscribeOperation{baseOperation: baseOperation{operation: Subscribe}}
	default:
		return nil, fmt.Errorf("Invalid operation: %v", operJSON["operation"].(string))
	}

	if err := oper.Load(ctx, operJSON); err != nil {
		return nil, fmt.Errorf("Failed to parse operation %v, error %v", operJSON["operation"].(string), err)
	}

	return oper, nil
}

// Methods for baseOperation
func (bo *baseOperation) Oper() op_t {
	return bo.operation
}

func (bo *baseOperation) Desc() string {
	return bo.desc
}

// Methods for Operation
// Loads JSON operation map operJSON.
func (oper *baseOperation) Load(ctx context.Context, operJSON map[string]interface{}) error {
	rt, err := operJSON["returnCode"].(json.Number).Int64()
	if err != nil {
		return err
	}
	oper.wantRetCode = codes.Code(rt)

	if v, ok := operJSON["title"]; ok {
		oper.desc = v.(string)
	}

	// Uses text proto request if operProto is defined.
	if operProto, ok := operJSON["operProto"]; ok {
		switch oper.operation {
		case Get:
			oper.pbReq = &pb.GetRequest{}
		case Update, Replace, Delete:
			oper.pbReq = &pb.SetRequest{}
		case Subscribe:
			oper.pbReq = &pb.SubscribeRequest{}
		default:
			return fmt.Errorf("Invalid oper:%v", oper.operation)
		}
		pbTxt := operProto.(string)
		if err := proto.UnmarshalText(pbTxt, oper.pbReq); err != nil {
			return fmt.Errorf("Failed to unmarshal proto (%v): %v", pbTxt, err)
		}
		if len(oper.desc) == 0 {
			oper.desc = operJSON["operation"].(string) + ":" + pbTxt
		}
	} else {
		// For legacy tests.
		path, err := xpath.ToGNMIPath(operJSON["xpath"].(string))
		if err != nil {
			return fmt.Errorf("error in parsing xpath %q to gnmi path, %v", path, err)
		}
		oper.textPbPath = proto.CompactTextString(path)
		if operJSON["xpath"].(string) == "/" {
			oper.textPbPath = "elem:<name:\"openconfig\">"
		}
		if len(oper.desc) == 0 {
			oper.desc = operJSON["operation"].(string) + ":" + oper.textPbPath
		}

		getType, ok := operJSON["getType"]
		if ok {
			switch strings.ToLower(getType.(string)) {
			case "all":
				oper.getDataType = pb.GetRequest_ALL
			case "config":
				oper.getDataType = pb.GetRequest_CONFIG
			case "state":
				oper.getDataType = pb.GetRequest_STATE
			case "operational":
				oper.getDataType = pb.GetRequest_OPERATIONAL
			default:
				return fmt.Errorf("Unexpected \"getType\", got %#v", getType)
			}
		} else {
			oper.getDataType = pb.GetRequest_ALL
		}
	}

	if val, ok := operJSON["target"]; ok {
		oper.pathTarget = val.(string)
	}

	if val, ok := operJSON["origin"]; ok {
		oper.origin = val.(string)
	}

	if val, ok := operJSON["attributeData"]; ok {
		oper.attributeData = val.(string)
	}

	// Loads sub operations.
	if vals, ok := operJSON["subOpers"]; ok {
		for _, val := range vals.([]interface{}) {
			jsonSubOper := val.(map[string]interface{})
			// Adds global definitions to jsonSubOper so they can be referenced in sub operations.
			jsonSubOper[SchemaIDGDef], _ = operJSON[SchemaIDGDef]
			subOper, err := NewSubOperation(ctx, oper, jsonSubOper)
			if err != nil {
				return err
			}
			oper.subOpers = append(oper.subOpers, subOper)
		}
	}

	// Operation may not have a validator. Validations may be in sub-operations.
	if _, ok := operJSON["type"]; ok {
		if oper.operation == Subscribe {
			return fmt.Errorf("Please use \"validate\" sub-operation to validate subscribe response (%s)", oper.desc)
		}
		// For legacy get/set tests.
		oper.schema = gojsonschema.NewGoLoader(operJSON)
	}

	return nil
}

func (oper *baseOperation) Execute(t *testing.T, ctx context.Context) {
	t.Fatal("Execute is not implemented:%v", oper.Desc())
}

// Methods for getOperation
// TODO(b/<>): Support PROTO encoding for getOperation if needed.
func (geto *getOperation) Execute(t *testing.T, ctx context.Context) {
	// Send request
	var req *pb.GetRequest
	if geto.pbReq != nil {
		// Uses prot request if it is defined.
		req = geto.pbReq.(*pb.GetRequest)
	} else {
		// For legacy tests.
		var path []*pb.Path = nil
		if len(geto.textPbPath) > 0 {
			var pbPath pb.Path
			if err := proto.UnmarshalText(geto.textPbPath, &pbPath); err != nil {
				t.Fatalf("error in unmarshaling path: %v %v", geto.textPbPath, err)
			}
			path = []*pb.Path{&pbPath}
		}
		prefix := pb.Path{Origin: geto.origin, Target: geto.pathTarget}
		req = &pb.GetRequest{
			Prefix:   &prefix,
			Path:     path,
			Encoding: pb.Encoding_JSON_IETF,
			Type:     geto.getDataType,
		}
	}

	// Gets grpc connection from context ctx and creates a gNMI client.
	conn := ctx.Value(CtxIDGChannel).(*grpc.ClientConn)
	gClient := pb.NewGNMIClient(conn)

	resp, err := gClient.Get(ctx, req)

	// Check return code
	gotRetStatus, ok := status.FromError(err)
	if !ok {
		t.Fatalf("got a non-grpc error from grpc call")
	}
	var jsonIETFVal string
	if gotRetStatus.Code() != geto.wantRetCode {
		t.Log("err: ", err)
		t.Fatalf("got return code %v(%d), want %v in operation \"%s\"", gotRetStatus.Code(), gotRetStatus.Code(), geto.wantRetCode, geto.baseOperation.desc)
	}

	// Check response value
	var gotVal interface{}
	if resp != nil {
		notifs := resp.GetNotification()
		if len(notifs) != 1 {
			t.Fatalf("got %d notifications, want 1", len(notifs))
		}
		updates := notifs[0].GetUpdate()
		if len(updates) != 1 {
			t.Fatalf("got %d updates in the notification, want 1", len(updates))
		}
		val := updates[0].GetVal()
		if val.GetJsonIetfVal() == nil {
			gotVal, err = value.ToScalar(val)
			if err != nil {
				t.Errorf("got: %v, want a scalar value", gotVal)
			}
		} else {
			jsonIETFVal = string(val.GetJsonIetfVal())
		}
	}

	if geto.schema != nil {
		if len(jsonIETFVal) == 0 {
			jsonIETFVal = "{}"
		}
		docLoader := gojsonschema.NewStringLoader(jsonIETFVal)
		result, err := gojsonschema.Validate(geto.schema, docLoader)
		if err != nil {
			t.Fatalf("Error validating JSON schema: %v", err)
		}
		if !result.Valid() {
			for _, desc := range result.Errors() {
				t.Logf("- %s\n", desc)
			}
			t.Logf("\nInvalid JSON Response:\n%v\n\n", jsonIETFVal)
			t.Fatalf("The response JSON is not valid in operation \"%s\"", geto.baseOperation.desc)
		}
	} else if geto.wantRetCode == 0 {
		t.Fatalf("Get operation \"%s\" expects success but no schema was provided, update the testcase to include one", geto.baseOperation.desc)
	}

	// Execute sub operations.
	for _, subOper := range geto.subOpers {
		t.Logf("Executing suboper: %v", subOper.Desc())
		subOper.Execute(t, ctx)
	}
}

// Methods for setOperation
func extractJSON(val string) []byte {
	if jsonBytes, err := ioutil.ReadFile(val); err == nil {
		return jsonBytes
	}
	return []byte(val)
}

func (seto *setOperation) Execute(t *testing.T, ctx context.Context) {
	// Send request
	var req *pb.SetRequest

	if seto.pbReq != nil {
		req = seto.pbReq.(*pb.SetRequest)
	} else {
		// For legacy tests.
		var pbPath pb.Path
		if err := proto.UnmarshalText(seto.textPbPath, &pbPath); err != nil {
			t.Fatalf("error in unmarshaling path: %v %v", seto.textPbPath, err)
		}
		prefix := pb.Path{Target: seto.pathTarget}
		req = &pb.SetRequest{Prefix: &prefix}

		switch seto.operation {
		case Replace:
			v := &pb.TypedValue{
				Value: &pb.TypedValue_JsonIetfVal{JsonIetfVal: extractJSON(seto.attributeData)}}

			req = &pb.SetRequest{
				Replace: []*pb.Update{&pb.Update{Path: &pbPath, Val: v}},
			}
		case Update:
			v := &pb.TypedValue{
				Value: &pb.TypedValue_JsonIetfVal{JsonIetfVal: extractJSON(seto.attributeData)}}

			req = &pb.SetRequest{
				Update: []*pb.Update{&pb.Update{Path: &pbPath, Val: v}},
			}
		case Delete:
			req = &pb.SetRequest{
				Delete: []*pb.Path{&pbPath},
			}
		}
	}

	conn := ctx.Value(CtxIDGChannel).(*grpc.ClientConn)
	gClient := pb.NewGNMIClient(conn)
	_, err := gClient.Set(ctx, req)

	gotRetStatus, ok := status.FromError(err)
	if !ok {
		t.Fatal("got a non-grpc error from grpc call")
	}
	if gotRetStatus.Code() != seto.wantRetCode {
		t.Fatalf("err: %v\n got return code %v(%d), want %v in operation \"%s\"", err, gotRetStatus.Code(), gotRetStatus.Code(), seto.wantRetCode, seto.baseOperation.desc)
	}

	// Execute sub operations.
	for _, subOper := range seto.subOpers {
		t.Logf("Executing suboper: %v", subOper.Desc())
		subOper.Execute(t, ctx)
	}
}

// Methods for subscribeSession
// Returns notification channel
func (ss *subscribeSession) notification() chan interface{} {
	return ss.chNtfy
}

// Closes session.
func (ss *subscribeSession) close() {
	ss.done.Store(true)
}

// Starts a subscribe session.
func startSubscribe(ctx context.Context, req *pb.SubscribeRequest) (*subscribeSession, error) {
	conn := ctx.Value(CtxIDGChannel).(*grpc.ClientConn)
	gClient := pb.NewGNMIClient(conn)
	subClient, err := gClient.Subscribe(ctx)
	if err != nil {
		return nil, fmt.Errorf("Failed to subscribe:%v", err)
	}

	if err = subClient.Send(req); err != nil {
		return nil, fmt.Errorf("Failed to send subscribe request:%v", err)
	}

	subSess := &subscribeSession{subClient: subClient, chNtfy: make(chan interface{})}

	// Routine to receive responses.
	go func() {
		defer close(subSess.chNtfy)

		for subSess.done.Load() == false {
			resp, err := subClient.Recv()

			// Check return code
			gotRetStatus, ok := status.FromError(err)
			if !ok {
				subSess.chNtfy <- fmt.Errorf("got a non-grpc error from grpc call")
				return
			}
			if gotRetStatus.Code() != 0 {
				// Use select w/ default to prevent the channel send from
				// blocking forever if the listner has already exited.
				select {
				case subSess.chNtfy <- fmt.Errorf("got return code %v, error:%v", gotRetStatus.Code(), err):
				default:
				}
				return
			}

			fmt.Printf("receive SubResp:%+v\n", proto.CompactTextString(resp))
			if sr := resp.GetSyncResponse(); sr {
				subSess.chNtfy <- sr
				continue
			}
			if notif := resp.GetUpdate(); notif != nil {
				subSess.chNtfy <- notif
			}
		}
	}()

	return subSess, nil
}

// returns JSON_IETF encoded update payload.
// Works for both JSON_IETF encoded and PROTO encoded update.
func getUpdateJSONVal(prefix *pb.Path, upd *pb.Update) string {
	var jsonIetfVal string = "{}"
	tv := upd.GetVal()
	if tv.GetJsonIetfVal() == nil {
		// converts proto val to json for validation.
		// We only support scalar value update here.
		updPath := getFullPath(prefix, upd.GetPath())
		rootObj := &ocbinds.Device{}
		if err := ytypes.SetNode(ygSchema.RootSchema(), rootObj, updPath, tv, &ytypes.InitMissingElements{}); err != nil {
			fmt.Printf("Update node error!", err)
			return jsonIetfVal
		}
		parentPath := getParentPath(updPath)
		updNode, _, err := ytypes.GetOrCreateNode(ygSchema.RootSchema(), rootObj, parentPath)
		if err != nil {
			fmt.Println("Cannot retrieve node for ", parentPath)
			return jsonIetfVal
		}
		if jsonIetfVal, err = ygot.EmitJSON(updNode.(ygot.ValidatedGoStruct), &ygot.EmitJSONConfig{
			Format:         ygot.RFC7951,
			Indent:         "  ",
			SkipValidation: true,
			RFC7951Config: &ygot.RFC7951JSONConfig{
				AppendModuleName: true,
			},
		}); err != nil {
			fmt.Println("Failed to generate JSON:", err)
			return "{}"
		}
	} else {
		jsonIetfVal = string(tv.GetJsonIetfVal())
	}

	if len(jsonIetfVal) == 0 {
		jsonIetfVal = "{}"
	}

	return jsonIetfVal
}

// Validates an update using provided schema.
func validateUpdate(prefix *pb.Path, upd *pb.Update, schema gojsonschema.JSONLoader) error {
	if schema == nil {
		fmt.Println("Validating with no schema.")
		return nil
	}

	fmt.Println("Validating...")
	jsonIetfVal := getUpdateJSONVal(prefix, upd)
	docLoader := gojsonschema.NewStringLoader(jsonIetfVal)
	result, err := gojsonschema.Validate(schema, docLoader)
	if err != nil {
		return fmt.Errorf("Error validating response JSON:\n%v", err)
	}
	if !result.Valid() {
		return fmt.Errorf("Validate Error:\n%v\nInvalid JSON Response:\n%v\n\n", result.Errors(), jsonIetfVal)
	}
	return nil
}

// Methods for subscribeOperation
func (sbo *subscribeOperation) Execute(t *testing.T, ctx context.Context) {
	if sbo.pbReq == nil {
		t.Fatal("No subscribe request specified.")
	}

	// Creates a new context.
	subCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	subSess, err := startSubscribe(subCtx, sbo.pbReq.(*pb.SubscribeRequest))
	if err != nil {
		t.Fatal(err)
	}
	defer subSess.close()

	// Add subscribe session in subscribe context.
	subCtx = context.WithValue(subCtx, CtxIDSubscribeSess, subSess)
	// Execute sub operations.
	for _, subOper := range sbo.subOpers {
		t.Logf("Executing suboper: %v", subOper.Desc())
		subOper.Execute(t, subCtx)
	}
}
