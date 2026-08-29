package transl_utils

import (
	"context"
	"errors"
	"testing"

	"github.com/Azure/sonic-mgmt-common/translib"
	"github.com/Azure/sonic-mgmt-common/translib/tlerr"
	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/sonic-net/sonic-gnmi/common_utils"
	"github.com/stretchr/testify/assert"
)

func TestToStatus(t *testing.T) {

	ToStatus(nil)
	ToStatus(tlerr.AuthorizationError{})
	ToStatus(tlerr.TranslibSyntaxValidationError{
		StatusCode: 0,
		ErrorStr:   errors.New("Random syntax error occurred"),
	})
	ToStatus(tlerr.TranslibUnsupportedClientVersion{
		ClientVersion: "1.0",
	})
	ToStatus(tlerr.InternalError{
		Path: "something",
	})

	ToStatus(tlerr.NotFoundError{
		Path: "something",
	})
	ToStatus(tlerr.AlreadyExistsError{
		Path: "something",
	})
	ToStatus(tlerr.TranslibCVLFailure{
		Code: 1001,
	})
	ToStatus(tlerr.TranslibTransactionFail{})
	ToStatus(tlerr.TranslibRedisClientEntryNotExist{
		Entry: "Redis",
	})
	ToStatus(tlerr.TranslibDBScriptFail{
		Description: "script fail",
	})
}

func TestTranslProcessGet_Success_Proto(t *testing.T) {
	// 1. Save original function and restore after test
	origGet := translibGet
	defer func() { translibGet = origGet }()

	// 2. Define the mock behavior
	expectedPayload := []byte("mock data")
	translibGet = func(req translib.GetRequest) (translib.GetResponse, error) {
		return translib.GetResponse{
			Payload: expectedPayload,
		}, nil
	}

	// 3. Setup context (ensure common_utils.GetContext won't crash)
	// You might need to populate the context with Auth/Bundle version if your code reads it
	ctx := context.Background()

	// 4. Execute
	typedVal, resp, err := TranslProcessGet("/access-list", nil, ctx, gnmipb.Encoding_PROTO)

	// 5. Assertions
	assert.NoError(t, err)
	assert.Nil(t, typedVal, "PROTO encoding should return nil for TypedValue")
	assert.NotNil(t, resp, "PROTO encoding should return the translib response")
	assert.Equal(t, expectedPayload, resp.Payload)
}

func TestTranslProcessGet_Success_JSON(t *testing.T) {
	origGet := translibGet
	defer func() { translibGet = origGet }()

	translibGet = func(req translib.GetRequest) (translib.GetResponse, error) {
		return translib.GetResponse{
			Payload: []byte(`{ "foo": "bar" }`),
		}, nil
	}

	typedVal, _, err := TranslProcessGet("/any-path", nil, context.Background(), gnmipb.Encoding_JSON_IETF)

	assert.NoError(t, err)
	assert.NotNil(t, typedVal)
	// Check for compacted JSON (no spaces)
	assert.Equal(t, []byte(`{"foo":"bar"}`), typedVal.GetJsonIetfVal())
}

func TestTranslProcessGet_ContentFromDataType(t *testing.T) {
	origGet := translibGet
	defer func() { translibGet = origGet }()

	tests := []struct {
		name    string
		dt      gnmipb.GetRequest_DataType
		want    string
		setType bool
	}{
		{name: "default all", want: translib.QueryParametersContentAll},
		{name: "ALL", dt: gnmipb.GetRequest_ALL, want: translib.QueryParametersContentAll, setType: true},
		{name: "CONFIG", dt: gnmipb.GetRequest_CONFIG, want: translib.QueryParametersContentConfig, setType: true},
		{name: "STATE", dt: gnmipb.GetRequest_STATE, want: translib.QueryParametersContentState, setType: true},
		{name: "OPERATIONAL", dt: gnmipb.GetRequest_OPERATIONAL, want: translib.QueryParametersContentOperational, setType: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotContent string
			translibGet = func(req translib.GetRequest) (translib.GetResponse, error) {
				gotContent = req.QueryParams.Content
				return translib.GetResponse{Payload: []byte(`{}`)}, nil
			}
			ctx := context.Background()
			if tt.setType {
				_, ctx = common_utils.GetContext(ctx)
				common_utils.SetReqParam(ctx, common_utils.KeyGetDataType, tt.dt)
			}
			_, _, err := TranslProcessGet("/any-path", nil, ctx, gnmipb.Encoding_JSON_IETF)
			assert.NoError(t, err)
			assert.Equal(t, tt.want, gotContent)
		})
	}
}
