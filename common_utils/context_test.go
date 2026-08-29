package common_utils

import (
	"context"
	"testing"
)

func TestRetiredCounterSlotsRemainStable(t *testing.T) {
	tests := []struct {
		counter CounterType
		ordinal int
		name    string
	}{
		{DBUS_FILE_STAT, 23, "DBUS file stat"},
		{DBUS_FILE_DOWNLOAD, 24, "DBUS file download"},
		{DBUS_FILE_REMOVE, 25, "DBUS file remove"},
		{DBUS_IMAGE_DOWNLOAD, 26, "DBUS image download"},
		{DBUS_IMAGE_INSTALL, 27, "DBUS image install"},
		{DBUS_IMAGE_LIST, 28, "DBUS image list"},
		{DBUS_IMAGE_ACTIVATE, 29, "DBUS image activate"},
		{DBUS_DOCKER_LOAD, 30, "DBUS docker load"},
		{DBUS_CONFIG_REPLACE, 31, "DBUS config replace"},
	}

	for _, test := range tests {
		if got := int(test.counter); got != test.ordinal {
			t.Errorf("%s ordinal = %d, want %d", test.name, got, test.ordinal)
		}
		if got := test.counter.String(); got != test.name {
			t.Errorf("CounterType(%d).String() = %q, want %q", test.ordinal, got, test.name)
		}
	}

	if got, want := int(COUNTER_SIZE), 32; got != want {
		t.Errorf("COUNTER_SIZE = %d, want %d", got, want)
	}
}

func TestReqParamUnknownKey(t *testing.T) {
	ctx := context.Background()
	val, ok := ReqParam(ctx, "foo")
	if ok {
		t.Fatalf("ReqParam didn't return false for unknown key")
	}
	if val != nil {
		t.Fatalf("ReqParam didn't return nil for unknown key")
	}
}

func TestSetReqParamRoundTrip(t *testing.T) {
	_, ctx := GetContext(context.Background())
	SetReqParam(ctx, KeyGetDataType, "STATE")
	val, ok := ReqParam(ctx, KeyGetDataType)
	if !ok {
		t.Fatalf("ReqParam missed a value that was SetReqParam'd")
	}
	if val != "STATE" {
		t.Fatalf("ReqParam got %v, want STATE", val)
	}
}
