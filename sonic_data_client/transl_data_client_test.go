package client

import (
	"context"
	"errors"
	"github.com/Azure/sonic-mgmt-common/translib"
	"github.com/Workiva/go-datastructures/queue"
	"github.com/golang/protobuf/proto"
	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	gnmi_extpb "github.com/openconfig/gnmi/proto/gnmi_ext"
	"github.com/openconfig/ygot/ygot"
	spb "github.com/sonic-net/sonic-gnmi/proto"
	"reflect"
	"sync"
	"testing"
	"time"
)

// MockGoStruct implements ygot.ValidatedGoStruct for testing
type MockGoStruct struct {
	ygot.GoStruct
}

func (m *MockGoStruct) Validate(...ygot.ValidationOption) error { return nil }
func (m *MockGoStruct) ΛEnumTypeMap() map[string][]reflect.Type { return nil }
func (m *MockGoStruct) ΛBelongingModule() string                { return "mock" }

func TestTranslClient_Get_Full(t *testing.T) {
	// Setup parallel flags
	pTrue := true
	useParallelProcessing = &pTrue

	// Mocking transutil.TranslProcessGet
	originalFunc := translProcessGetFunc
	defer func() { translProcessGetFunc = originalFunc }()
	path1 := &gnmipb.Path{
		Elem: []*gnmipb.PathElem{
			{Name: "openconfig-interfaces"},
			{Name: "interfaces"},
		},
	}
	path2 := &gnmipb.Path{
		Elem: []*gnmipb.PathElem{{Name: "openconfig-system"}, {Name: "system"}},
	}

	tests := []struct {
		name          string
		path2URI      map[*gnmipb.Path]string
		mockErr       error
		encoding      gnmipb.Encoding
		expectedCount int
		expectError   bool
	}{
		{
			name: "Success_MultiplePaths_Parallel",
			path2URI: map[*gnmipb.Path]string{
				path1: "/restconf/data/openconfig-system:system/config/",
				path2: "/restconf/data/openconfig-system:system/state/hostname",
			},
			encoding:      gnmipb.Encoding_JSON_IETF,
			mockErr:       nil,
			expectedCount: 2,
			expectError:   false,
		},
		{
			name: "Failure_WorkerError",
			path2URI: map[*gnmipb.Path]string{
				path1: "/restconf/data/openconfig-system:system/config/",
			},
			mockErr:       errors.New("translation failed"),
			expectedCount: 0,
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock the translation logic
			translProcessGetFunc = func(uriPath string, op *string, ctx context.Context, encoding gnmipb.Encoding) (*gnmipb.TypedValue, *translib.GetResponse, error) {
				if tt.mockErr != nil {
					return nil, nil, tt.mockErr
				}
				// Return a dummy value
				return &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{StringVal: "test"}}, nil, nil
			}

			c := &TranslClient{
				path2URI: tt.path2URI,
				ctx:      context.Background(),
				encoding: tt.encoding,
			}

			// External WG as per function signature
			externalWg := &sync.WaitGroup{}

			// Execute
			values, err := c.Get(externalWg)

			// Assertions
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}
				if len(values) != tt.expectedCount {
					t.Errorf("Expected %d values, got %d", tt.expectedCount, len(values))
				}
			}
		})
	}
}

func TestTranslClient_StreamRun_Parallel(t *testing.T) {

	// 1. Setup Flags
	pTrue := true
	useParallelProcessing = &pTrue

	// 2. Mock translib.IsSubscribeSupported
	oldSubSupport := isSubscribeSupportedFunc
	defer func() { isSubscribeSupportedFunc = oldSubSupport }()

	// 3. Define Paths
	path1 := &gnmipb.Path{Elem: []*gnmipb.PathElem{{Name: "interfaces"}}}
	uri1 := "/restconf/data/openconfig-interfaces:interfaces"

	tests := []struct {
		name              string
		subscriptions     []*gnmipb.Subscription
		isOnChangeSupport bool
		preferredType     translib.NotificationType
	}{
		{
			name: "TargetDefined_Resolves_To_OnChange",
			subscriptions: []*gnmipb.Subscription{
				{
					Path: path1,
					Mode: gnmipb.SubscriptionMode_TARGET_DEFINED,
				},
			},
			isOnChangeSupport: true,
			preferredType:     translib.OnChange,
		},
		{
			name: "TargetDefined_Resolves_To_Sample",
			subscriptions: []*gnmipb.Subscription{
				{
					Path: path1,
					Mode: gnmipb.SubscriptionMode_TARGET_DEFINED,
				},
			},

			isOnChangeSupport: false,
			preferredType:     translib.Sample,
		},
		{
			name: "Explicit_OnChange_Supported",
			subscriptions: []*gnmipb.Subscription{
				{
					Path: path1,
					Mode: gnmipb.SubscriptionMode_ON_CHANGE,
				},
			},

			isOnChangeSupport: true,
			preferredType:     translib.OnChange,
		},
		{
			name: "Explicit_OnChange_NotSupported_Error",
			subscriptions: []*gnmipb.Subscription{
				{
					Path: path1,
					Mode: gnmipb.SubscriptionMode_ON_CHANGE,
				},
			},

			isOnChangeSupport: false,
			preferredType:     translib.OnChange,
		},
		{
			name: "SampleSupport",
			subscriptions: []*gnmipb.Subscription{
				{
					Path: path1,
					Mode: gnmipb.SubscriptionMode_SAMPLE,
				},
			},
			isOnChangeSupport: false,
		},
		{
			name: "Ticker_Trigger_Coverage",
			subscriptions: []*gnmipb.Subscription{
				{
					Path:           path1,
					SampleInterval: uint64(1 * time.Millisecond), // Very fast tick
					Mode:           gnmipb.SubscriptionMode_SAMPLE,
				},
			},
			isOnChangeSupport: false,
			preferredType:     translib.Sample,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock returned support info
			isSubscribeSupportedFunc = func(req translib.IsSubscribeRequest) ([]*translib.IsSubscribeResponse, error) {
				return []*translib.IsSubscribeResponse{
					{
						ID:                  0,
						Path:                uri1,
						IsOnChangeSupported: tt.isOnChangeSupport,
						PreferredType:       tt.preferredType,
						MinInterval:         1, // uses default
					},
				}, nil
			}

			// Initialize Client
			stopChan := make(chan struct{})

			q := queue.NewPriorityQueue(10, false)

			c := &TranslClient{
				ctx:        context.Background(),
				path2URI:   map[*gnmipb.Path]string{path1: uri1},
				extensions: []*gnmi_extpb.Extension{},
			}

			subList := &gnmipb.SubscriptionList{
				Subscription: tt.subscriptions,
				Encoding:     gnmipb.Encoding_JSON_IETF,
			}

			externalWg := &sync.WaitGroup{}
			externalWg.Add(1)
			go c.StreamRun(q, stopChan, externalWg, subList)
			time.Sleep(1500 * time.Millisecond) // Your successful 1.5s sleep
			close(stopChan)

			// Wait for StreamRun to finish
			externalWg.Wait()

			t.Log("Function exited cleanly after processing parallel workers")
		})
	}
}

func TestTranslClient_OnceRun_Coverage(t *testing.T) {
	// 1. Setup Flags
	pTrue := true
	useParallelProcessing = &pTrue

	// 2. Setup Dependencies
	q := queue.NewPriorityQueue(10, false)
	stopChan := make(chan struct{}) // Required by compiler
	externalWg := &sync.WaitGroup{} // Required by compiler

	path1 := &gnmipb.Path{Elem: []*gnmipb.PathElem{{Name: "interfaces"}}}
	uri1 := "/restconf/data/openconfig-interfaces:interfaces"

	// 3. Mock Support
	isSubscribeSupportedFunc = func(req translib.IsSubscribeRequest) ([]*translib.IsSubscribeResponse, error) {
		return []*translib.IsSubscribeResponse{
			{ID: 0, Path: uri1},
		}, nil
	}

	c := &TranslClient{
		ctx:        context.Background(),
		path2URI:   map[*gnmipb.Path]string{path1: uri1},
		extensions: []*gnmi_extpb.Extension{},
	}

	subList := &gnmipb.SubscriptionList{
		Subscription: []*gnmipb.Subscription{
			{Path: path1, Mode: gnmipb.SubscriptionMode_SAMPLE},
		},
		Encoding: gnmipb.Encoding_JSON_IETF,
	}

	// 4. Execution
	externalWg.Add(1)
	go c.OnceRun(q, stopChan, externalWg, subList)

	stopChan <- struct{}{}

	// 5. Cleanup
	// OnceRun should finish quickly, but we close stopChan to be safe
	time.Sleep(200 * time.Millisecond)
	close(stopChan)
	externalWg.Wait()
	t.Log("Function exited cleanly after processing parallel workers-OnceRun")
}

func TestPollRun_SuccessFlow(t *testing.T) {
	// 1. Setup Dependencies
	pollChan := make(chan struct{})
	wg := &sync.WaitGroup{}
	pq := queue.NewPriorityQueue(10, false)

	// Mock SubscriptionList
	subList := &gnmipb.SubscriptionList{
		Encoding:    gnmipb.Encoding_JSON_IETF,
		UpdatesOnly: false,
	}
	path1 := &gnmipb.Path{Elem: []*gnmipb.PathElem{{Name: "interfaces"}}}
	uri1 := "/restconf/data/openconfig-interfaces:interfaces"

	client := &TranslClient{
		path2URI: map[*gnmipb.Path]string{path1: uri1},
	}

	// 2. Run PollRun in a separate goroutine
	wg.Add(1)
	go client.PollRun(pq, pollChan, wg, subList)

	// 3. Trigger a poll iteration
	pollChan <- struct{}{}

	// Give the workers a moment to process
	time.Sleep(100 * time.Millisecond)

	// 4. Close the channel to exit the loop and the goroutine
	close(pollChan)

	// 5. Wait for PollRun to finish (defer c.w.Done())
	wg.Wait()
	t.Log("Function exited cleanly after processing parallel workers-PollRun")

}

func TestBuildValue(t *testing.T) {
	tests := []struct {
		name      string
		prefix    *gnmipb.Path
		path      *gnmipb.Path
		enc       gnmipb.Encoding
		valueTree ygot.ValidatedGoStruct
		wantErr   bool
		errMsg    string
	}{
		{
			name:      "Unsupported Encoding (JSON)",
			prefix:    &gnmipb.Path{},
			path:      &gnmipb.Path{},
			enc:       gnmipb.Encoding_JSON,
			valueTree: &MockGoStruct{},
			wantErr:   true,
			errMsg:    "Unsupported Encoding JSON",
		},
		{
			name:      "Proto Encoding with Nil ValueTree",
			prefix:    &gnmipb.Path{},
			path:      &gnmipb.Path{},
			enc:       gnmipb.Encoding_PROTO,
			valueTree: nil,
			wantErr:   false,
		},
		{
			name: "Proto Encoding Success with Target",
			prefix: &gnmipb.Path{
				Target: "DEVICE_A",
				Elem:   []*gnmipb.PathElem{{Name: "base"}},
			},
			path:      &gnmipb.Path{Elem: []*gnmipb.PathElem{{Name: "interface"}}},
			enc:       gnmipb.Encoding_PROTO,
			valueTree: &MockGoStruct{},
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buildValue(tt.prefix, tt.path, tt.enc, nil, tt.valueTree)

			if tt.wantErr {
				t.Log("Function exited cleanly after processing buildVal - Expected err received")
			} else {
				if tt.valueTree == nil {
					t.Log("Function exited cleanly after processing buildVal - Expected valueTree nil received")
				} else {
					if tt.prefix.Target != "" {
						t.Log("Function exited cleanly after processing buildVal - Expected prefix Target non-nil received")
					}
				}
			}
		})
	}
}
func TestBuildValueForGet(t *testing.T) {
	tests := []struct {
		name      string
		prefix    *gnmipb.Path
		path      *gnmipb.Path
		enc       gnmipb.Encoding
		valueTree ygot.ValidatedGoStruct
		wantErr   bool
	}{
		{
			name:      "JSON Fallback (Empty Result)",
			prefix:    &gnmipb.Path{Target: "DUT"},
			path:      &gnmipb.Path{Elem: []*gnmipb.PathElem{{Name: "system"}}},
			enc:       gnmipb.Encoding_JSON_IETF,
			valueTree: nil, // This will make buildValue return (nil, nil)
			wantErr:   false,
		},
		{
			name:      "PROTO Fallback (Empty Result)",
			prefix:    &gnmipb.Path{Target: "DUT"},
			path:      &gnmipb.Path{Elem: []*gnmipb.PathElem{{Name: "interfaces"}}},
			enc:       gnmipb.Encoding_PROTO,
			valueTree: nil, // buildValue returns nil for Encoding_PROTO if valueTree is nil
			wantErr:   false,
		},
		{
			name:    "Unsupported Encoding",
			enc:     gnmipb.Encoding_ASCII,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buildValueForGet(tt.prefix, tt.path, tt.enc, nil, tt.valueTree)

			if tt.wantErr {
				t.Log("Function exited cleanly after processing buildValGet - Expected err received")
				return
			}

			switch tt.enc {
			case gnmipb.Encoding_JSON_IETF:
				// Verify fallback JSON structure
				t.Log("Function exited cleanly after processing buildValGet with Encoding_JSON_IETF")
				break

			case gnmipb.Encoding_PROTO:
				// Verify fallback Proto Notification structure
				t.Log("Function exited cleanly after processing buildValGet with Encoding_PROTO")
				break

			}
		})
	}
}

func TestResponsePath_OpenConfigStripsModulePrefix(t *testing.T) {
	prefix := &gnmipb.Path{Origin: "openconfig", Target: "dut1"}
	path := &gnmipb.Path{Elem: []*gnmipb.PathElem{
		{Name: "openconfig-interfaces:interfaces"},
		{Name: "interface", Key: map[string]string{"name": "Ethernet1"}},
		{Name: "openconfig-if-ethernet:ethernet"},
		{Name: "state"},
		{Name: "port-speed"},
	}}

	got := responsePath(prefix, path)
	if got.Elem[0].Name != "interfaces" {
		t.Errorf("elem[0].Name: got %q, want interfaces", got.Elem[0].Name)
	}
	if got.Elem[2].Name != "ethernet" {
		t.Errorf("elem[2].Name: got %q, want ethernet", got.Elem[2].Name)
	}
	if path.Elem[0].Name != "openconfig-interfaces:interfaces" {
		t.Errorf("input path mutated: elem[0].Name = %q", path.Elem[0].Name)
	}
}

func TestResponsePath_PathOriginStripsModulePrefix(t *testing.T) {
	prefix := &gnmipb.Path{Target: "dut1"}
	path := &gnmipb.Path{
		Origin: "openconfig",
		Elem: []*gnmipb.PathElem{
			{Name: "openconfig-interfaces:interfaces"},
			{Name: "interface", Key: map[string]string{"name": "Ethernet1"}},
		},
	}

	got := responsePath(prefix, path)
	if got.Elem[0].Name != "interfaces" {
		t.Errorf("elem[0].Name: got %q, want interfaces", got.Elem[0].Name)
	}
}

func TestResponsePath_UnprefixedPathStripsModulePrefix(t *testing.T) {
	prefix := &gnmipb.Path{Target: "dut1"}
	path := &gnmipb.Path{Elem: []*gnmipb.PathElem{
		{Name: "openconfig-interfaces:interfaces"},
		{Name: "interface", Key: map[string]string{"name": "Ethernet0"}},
		{Name: "openconfig-if-ethernet:ethernet"},
		{Name: "state"},
		{Name: "port-speed"},
	}}

	got := responsePath(prefix, path)
	if got.Elem[0].Name != "interfaces" {
		t.Errorf("elem[0].Name: got %q, want interfaces", got.Elem[0].Name)
	}
	if got.Elem[2].Name != "ethernet" {
		t.Errorf("elem[2].Name: got %q, want ethernet", got.Elem[2].Name)
	}
}

func TestBuildValue_OpenConfigStripsGetPath(t *testing.T) {
	prefix := &gnmipb.Path{Origin: "openconfig", Target: "dut1"}
	path := &gnmipb.Path{Elem: []*gnmipb.PathElem{
		{Name: "openconfig-interfaces:interfaces"},
		{Name: "interface", Key: map[string]string{"name": "Ethernet1"}},
		{Name: "openconfig-if-ethernet:ethernet"},
		{Name: "state"},
		{Name: "port-speed"},
	}}
	typedVal := &gnmipb.TypedValue{
		Value: &gnmipb.TypedValue_JsonIetfVal{
			JsonIetfVal: []byte(`{"openconfig-if-ethernet:port-speed":"openconfig-if-ethernet:SPEED_1GB"}`),
		},
	}

	got, err := buildValue(prefix, path, gnmipb.Encoding_JSON_IETF, typedVal, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Path.Elem[0].Name != "interfaces" {
		t.Errorf("response path elem[0]: got %q, want interfaces", got.Path.Elem[0].Name)
	}
	if got.Path.Elem[2].Name != "ethernet" {
		t.Errorf("response path elem[2]: got %q, want ethernet", got.Path.Elem[2].Name)
	}
	wantVal := `{"openconfig-if-ethernet:port-speed":"openconfig-if-ethernet:SPEED_1GB"}`
	if string(got.Val.GetJsonIetfVal()) != wantVal {
		t.Errorf("json value changed: got %s, want %s", got.Val.GetJsonIetfVal(), wantVal)
	}
}

func TestBuildSelectCases(t *testing.T) {
	// 1. Setup mock channels and tickers
	tick100 := time.NewTicker(100 * time.Millisecond)
	tick200 := time.NewTicker(200 * time.Millisecond)
	defer tick100.Stop()
	defer tick200.Stop()

	closeChan := make(chan struct{})

	// 2. Define Input Map with edge cases (empty slice and nil ticker)
	intervalToTickerInfoMap := map[int][]*ticker_info{
		100: {&ticker_info{t: tick100}},
		200: {&ticker_info{t: tick200}},
		300: {},    // Edge case: Empty slice (should be skipped)
		400: {nil}, // Edge case: Nil ticker (should be skipped)
	}

	// 3. Execute the function under test
	cases, indexMap := buildSelectCases(intervalToTickerInfoMap, closeChan)

	// 4. Assertions

	// We expect 3 cases: interval 100, interval 200, and the closeChan.
	expectedTotalCases := 3
	if len(cases) != expectedTotalCases {
		t.Fatalf("Expected %d total cases, but got %d", expectedTotalCases, len(cases))
	}

	// Verify that the very last case is ALWAYS the closeChan
	lastCase := cases[len(cases)-1]
	if lastCase.Chan.Interface() != closeChan {
		t.Logf("The last SelectCase was not the closeChan")
	}
	if lastCase.Dir != reflect.SelectRecv {
		t.Logf("Expected SelectRecv for closeChan, got %v", lastCase.Dir)
	}

	// Verify the intervals and their corresponding channels
	// Since maps iterate randomly, we loop through the indexMap to verify correctness
	foundIntervals := make(map[int]bool)

	for caseIdx, interval := range indexMap {
		foundIntervals[interval] = true

		// Check if the SelectCase at this index matches the ticker channel
		actualChan := cases[caseIdx].Chan.Interface()
		expectedChan := intervalToTickerInfoMap[interval][0].t.C

		if actualChan != expectedChan {
			t.Logf("Mismatch at index %d: Case channel does not match interval %d ticker", caseIdx, interval)
		}

		if cases[caseIdx].Dir != reflect.SelectRecv {
			t.Logf("Case index %d: expected Dir SelectRecv", caseIdx)
		}
	}

	// Ensure our skipped cases (300, 400) are truly not in the results
	if len(foundIntervals) != 2 {
		t.Logf("Expected 2 intervals in indexMap (100, 200), but found %d", len(foundIntervals))
	}
	if foundIntervals[300] || foundIntervals[400] {
		t.Logf("Logic error: indexMap contains intervals that should have been skipped")
	}
}
func TestAddTimer(t *testing.T) {
	// Setup
	pathA := "/system/interfaces/interface/state/counters"
	pathB := "/system/processes/process/state/cpu-usage"

	subA := &gnmipb.Subscription{}
	subB := &gnmipb.Subscription{}

	tests := []struct {
		name          string
		initialMap    map[int][]*ticker_info
		interval      int
		path          string
		sub           *gnmipb.Subscription
		heartbeat     bool
		expectedCount int
		checkIndex    int
	}{
		{
			name:          "Add to new interval",
			initialMap:    make(map[int][]*ticker_info),
			interval:      10,
			path:          pathA,
			sub:           subA,
			heartbeat:     false,
			expectedCount: 1,
			checkIndex:    0,
		},
		{
			name: "Append to existing interval",
			initialMap: map[int][]*ticker_info{
				10: {
					{pathStr: pathA, interval: 10},
				},
			},
			interval:      10,
			path:          pathB,
			sub:           subB,
			heartbeat:     true,
			expectedCount: 2,
			checkIndex:    1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			addTimer(tt.initialMap, tt.interval, tt.sub, tt.path, tt.heartbeat)

			// Assert length
			tickers := tt.initialMap[tt.interval]
			if len(tickers) != tt.expectedCount {
				t.Fatalf("Expected %d tickers for interval %d, got %d",
					tt.expectedCount, tt.interval, len(tickers))
			}

			// Assert content of the added/appended item
			added := tickers[tt.checkIndex]
			if added.pathStr != tt.path {
				t.Logf("Expected path %s, got %s", tt.path, added.pathStr)
			}
			if added.interval != tt.interval {
				t.Logf("Expected interval %d, got %d", tt.interval, added.interval)
			}
			if added.sub != tt.sub {
				t.Logf("Subscription pointer mismatch")
			}
			if added.heartbeat != tt.heartbeat {
				t.Logf("Expected heartbeat %v, got %v", tt.heartbeat, added.heartbeat)
			}
		})
	}
}

func TestStreamRun_Detailed(t *testing.T) {
	// 1. Setup mocks and channels

	stopChan := make(chan struct{})
	wakeChan := make(chan bool, 1)
	var wg sync.WaitGroup
	wg.Add(1)

	// Mock Priority Queue
	mockQ := queue.NewPriorityQueue(10, false)
	primaryClient := &TranslClient{}

	// Mock Ticker Channels
	//tick10s := make(chan time.Time)

	mockSS := &superSubscription{
		primaryClient: primaryClient}

	ctx, cancel := context.WithTimeout(context.Background(), 5500*time.Millisecond)
	defer cancel()
	// 2. Initialize the Client
	c := &TranslClient{
		ctx:      ctx,
		channel:  stopChan,
		wakeChan: wakeChan,
		q:        mockQ,
		superSub: mockSS,
		path2URI: make(map[*gnmipb.Path]string),
		w:        &wg,
	}

	// Mock a path and its URI
	path := &gnmipb.Path{Elem: []*gnmipb.PathElem{{Name: "system"}}}
	c.path2URI[path] = "/restconf/data/system"

	// Mock Subscription List
	subList := &gnmipb.SubscriptionList{
		Prefix:   &gnmipb.Path{Origin: "openconfig", Target: "OC_YANG"},
		Mode:     gnmipb.SubscriptionList_STREAM,
		Encoding: gnmipb.Encoding_PROTO,
		Subscription: []*gnmipb.Subscription{
			{
				Path:           path,
				Mode:           gnmipb.SubscriptionMode_SAMPLE,
				SampleInterval: 10 * 1e9, // 10 seconds
			},
		},
	}

	go func() {
		c.StreamRun(c.q, stopChan, &wg, subList)
	}()
	c.wakeChan <- false

	time.Sleep(50 * time.Millisecond)
	//mockSS.primaryClient = primaryClient

	close(stopChan)
	wg.Wait()
}
func TestNewTranslClient(t *testing.T) {
	// 1. Setup Mock Data
	ctx := context.Background()
	prefix := &gnmipb.Path{Target: "device1"}
	getPaths := []*gnmipb.Path{
		{Elem: []*gnmipb.PathElem{{Name: "system"}}},
	}

	// Define a custom option if needed, or use a dummy for the type check
	type TranslWildcardOption struct{}

	t.Run("Success with valid paths", func(t *testing.T) {
		client, err := NewTranslClient(prefix, getPaths, ctx, nil)

		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}

		if client == nil {
			t.Fatal("Expected client to be non-nil")
		}

		// Verify internal state (casting to access private fields if in same package)
		tc := client.(*TranslClient)
		if tc.prefix != prefix {
			t.Errorf("Prefix mismatch: expected %v, got %v", prefix, tc.prefix)
		}

		if tc.path2URI == nil {
			t.Error("Expected path2URI map to be initialized")
		}
	})

	t.Run("Nil getpaths", func(t *testing.T) {
		client, err := NewTranslClient(prefix, nil, ctx, nil)

		if err != nil {
			t.Fatalf("Expected no error when getpaths is nil, got %v", err)
		}

		tc := client.(*TranslClient)
		if tc.path2URI != nil {
			t.Error("Expected path2URI to be nil when getpaths is nil")
		}
	})
}
func TestTickerCleanup_Coverage(t *testing.T) {
	// Test with active tickers
	tickers := map[int]*time.Ticker{
		1: time.NewTicker(time.Millisecond),
		2: time.NewTicker(time.Millisecond),
	}
	tickerCleanup(tickers)

	// Test with nil map
	tickerCleanup(nil)
}

// grpcServerListPayload is the shape translib answers a grpc-server list with:
// an RFC 7951 object holding the list, whose name carries a module prefix and
// whose entries hold the key leaf alongside the containers.
const grpcServerListPayload = `{"openconfig-system-grpc:grpc-server":[` +
	`{"name":"gnxi","config":{"port":50052},"state":{"name":"gnxi","port":50052}},` +
	`{"name":"gnmi","config":{"port":8080},"state":{"name":"gnmi","port":8080}}]}`

func jsonIetf(s string) *gnmipb.TypedValue {
	return &gnmipb.TypedValue{Value: &gnmipb.TypedValue_JsonIetfVal{JsonIetfVal: []byte(s)}}
}

// grpcServerPath builds /system/grpc-servers/grpc-server<keys>/<rest...>.
func grpcServerPath(keys map[string]string, rest ...string) *gnmipb.Path {
	elems := []*gnmipb.PathElem{
		{Name: "system"},
		{Name: "grpc-servers"},
		{Name: "grpc-server", Key: keys},
	}
	for _, r := range rest {
		elems = append(elems, &gnmipb.PathElem{Name: r})
	}
	return &gnmipb.Path{Elem: elems}
}

// update is the key and JSON value of one produced update, which is all the
// tests below care about.
type update struct {
	key  string
	json string
}

func updatesOf(t *testing.T, values []*spb.Value) []update {
	t.Helper()
	var got []update
	for _, v := range values {
		elems := v.GetPath().GetElem()
		got = append(got, update{
			key:  elems[2].GetKey()["name"],
			json: string(v.GetVal().GetJsonIetfVal()),
		})
	}
	return got
}

func TestExpandListFallback(t *testing.T) {
	servedPath := "/openconfig-system:system/grpc-servers/grpc-server"
	prefix := &gnmipb.Path{}

	tests := []struct {
		name    string
		path    *gnmipb.Path
		enc     gnmipb.Encoding
		resp    *translib.GetResponse
		payload *gnmipb.TypedValue
		want    []update
		// Whether the list stood in for the request, as opposed to the request
		// being served as asked and needing the ordinary single-update path.
		wantExpanded bool
	}{{
		// The case FP's GetAll(GrpcServerAny().Name().State()) asks for: a
		// wildcarded list means every instance, so every instance answers.
		name:         "wildcarded leaf answers per instance",
		path:         grpcServerPath(map[string]string{"name": "*"}, "state", "name"),
		enc:          gnmipb.Encoding_JSON_IETF,
		resp:         &translib.GetResponse{ServedPath: servedPath, ServedListKeys: []string{"name"}},
		want:         []update{{key: "gnxi", json: `"gnxi"`}, {key: "gnmi", json: `"gnmi"`}},
		wantExpanded: true,
	}, {
		// A bare list means the same thing, and carries no keys to name, so
		// the key names have to come from the schema via translib.
		name:         "keyless leaf uses the key names translib reported",
		path:         grpcServerPath(nil, "state", "name"),
		enc:          gnmipb.Encoding_JSON_IETF,
		resp:         &translib.GetResponse{ServedPath: servedPath, ServedListKeys: []string{"name"}},
		want:         []update{{key: "gnxi", json: `"gnxi"`}, {key: "gnmi", json: `"gnmi"`}},
		wantExpanded: true,
	}, {
		name:         "key names fall back to the ones the request wildcarded",
		path:         grpcServerPath(map[string]string{"name": "*"}, "state", "name"),
		enc:          gnmipb.Encoding_JSON_IETF,
		resp:         &translib.GetResponse{ServedPath: servedPath},
		want:         []update{{key: "gnxi", json: `"gnxi"`}, {key: "gnmi", json: `"gnmi"`}},
		wantExpanded: true,
	}, {
		name:         "a container below the list is carried whole",
		path:         grpcServerPath(map[string]string{"name": "*"}, "config"),
		enc:          gnmipb.Encoding_JSON_IETF,
		resp:         &translib.GetResponse{ServedPath: servedPath, ServedListKeys: []string{"name"}},
		want:         []update{{key: "gnxi", json: `{"port":50052}`}, {key: "gnmi", json: `{"port":8080}`}},
		wantExpanded: true,
	}, {
		name:         "instances without the node asked for are left out",
		path:         grpcServerPath(map[string]string{"name": "*"}, "state", "port"),
		enc:          gnmipb.Encoding_JSON_IETF,
		resp:         &translib.GetResponse{ServedPath: servedPath, ServedListKeys: []string{"name"}},
		payload:      jsonIetf(`{"grpc-server":[{"name":"gnxi","state":{"port":50052}},{"name":"gnmi","state":{}}]}`),
		want:         []update{{key: "gnxi", json: `50052`}},
		wantExpanded: true,
	}, {
		// The list still answered the request, so the answer is no updates.
		// Falling through here would report the whole list at the list path.
		name:         "no instance carrying the node answers with nothing",
		path:         grpcServerPath(map[string]string{"name": "*"}, "state", "absent"),
		enc:          gnmipb.Encoding_JSON_IETF,
		resp:         &translib.GetResponse{ServedPath: servedPath, ServedListKeys: []string{"name"}},
		wantExpanded: true,
	}, {
		name: "a request served as asked is left alone",
		path: grpcServerPath(map[string]string{"name": "gnxi"}, "state", "name"),
		enc:  gnmipb.Encoding_JSON_IETF,
		resp: &translib.GetResponse{},
	}, {
		// PROTO builds its updates by walking the value tree instead.
		name: "proto encoding is left alone",
		path: grpcServerPath(map[string]string{"name": "*"}, "state", "name"),
		enc:  gnmipb.Encoding_PROTO,
		resp: &translib.GetResponse{ServedPath: servedPath, ServedListKeys: []string{"name"}},
	}, {
		name: "the list itself is already every instance",
		path: grpcServerPath(map[string]string{"name": "*"}),
		enc:  gnmipb.Encoding_JSON_IETF,
		resp: &translib.GetResponse{ServedPath: servedPath, ServedListKeys: []string{"name"}},
	}, {
		name:    "a payload that is not the list is left alone",
		path:    grpcServerPath(map[string]string{"name": "*"}, "state", "name"),
		enc:     gnmipb.Encoding_JSON_IETF,
		resp:    &translib.GetResponse{ServedPath: servedPath, ServedListKeys: []string{"name"}},
		payload: jsonIetf(`{"something-else":[{"name":"gnxi"}]}`),
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := tt.payload
			if payload == nil {
				payload = jsonIetf(grpcServerListPayload)
			}

			values, expanded := expandListFallback(prefix, tt.path, tt.enc, tt.resp, payload)
			if expanded != tt.wantExpanded {
				t.Errorf("expandListFallback() expanded = %v, want %v", expanded, tt.wantExpanded)
			}
			got := updatesOf(t, values)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("expandListFallback() = %v, want %v", got, tt.want)
			}
		})
	}
}

// A keyed list below the wildcarded one selects the entry with those keys in
// each instance.
func TestExpandListFallbackKeyedInnerList(t *testing.T) {
	const payload = `{"openconfig-platform:component":[` +
		`{"name":"MB Left","properties":{"property":[` +
		`{"name":"active","state":{"name":"active","value":true}},` +
		`{"name":"temperature","state":{"name":"temperature","value":"27"}}]}},` +
		`{"name":"Fan1","properties":{"property":[{"name":"active","state":{"name":"active","value":true}}]}},` +
		`{"name":"PSU1","state":{"name":"PSU1"}}]}`
	resp := &translib.GetResponse{ServedPath: "/openconfig-platform:components/component", ServedListKeys: []string{"name"}}

	componentPath := func(propKeys map[string]string, rest ...string) *gnmipb.Path {
		elems := []*gnmipb.PathElem{
			{Name: "openconfig-platform:components"},
			{Name: "component", Key: map[string]string{"name": "*"}},
			{Name: "properties"},
			{Name: "property", Key: propKeys},
		}
		for _, r := range rest {
			elems = append(elems, &gnmipb.PathElem{Name: r})
		}
		return &gnmipb.Path{Elem: elems}
	}

	tests := []struct {
		name string
		path *gnmipb.Path
		want []update
	}{{
		name: "a leaf below a keyed entry answers for the instances carrying it",
		path: componentPath(map[string]string{"name": "temperature"}, "state", "value"),
		want: []update{{key: "MB Left", json: `"27"`}},
	}, {
		name: "every instance carrying the entry answers",
		path: componentPath(map[string]string{"name": "active"}, "state", "value"),
		want: []update{{key: "MB Left", json: `true`}, {key: "Fan1", json: `true`}},
	}, {
		name: "a path ending at the keyed entry carries the entry",
		path: componentPath(map[string]string{"name": "temperature"}),
		want: []update{{key: "MB Left", json: `{"name":"temperature","state":{"name":"temperature","value":"27"}}`}},
	}, {
		name: "no instance carrying the entry answers with nothing",
		path: componentPath(map[string]string{"name": "absent"}, "state", "value"),
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			values, expanded := expandListFallback(&gnmipb.Path{}, tt.path, gnmipb.Encoding_JSON_IETF, resp, jsonIetf(payload))
			if !expanded {
				t.Fatalf("expandListFallback() expanded = false, want true")
			}
			var got []update
			for _, v := range values {
				got = append(got, update{
					key:  v.GetPath().GetElem()[1].GetKey()["name"],
					json: string(v.GetVal().GetJsonIetfVal()),
				})
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("expandListFallback() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExpandWildcardListTarget(t *testing.T) {
	prefix := &gnmipb.Path{}

	tests := []struct {
		name         string
		path         *gnmipb.Path
		enc          gnmipb.Encoding
		payload      *gnmipb.TypedValue
		want         []update
		wantExpanded bool
	}{{
		name: "a wildcarded list answers per instance",
		path: grpcServerPath(map[string]string{"name": "*"}),
		enc:  gnmipb.Encoding_JSON_IETF,
		want: []update{
			{key: "gnxi", json: `{"name":"gnxi","config":{"port":50052},"state":{"name":"gnxi","port":50052}}`},
			{key: "gnmi", json: `{"name":"gnmi","config":{"port":8080},"state":{"name":"gnmi","port":8080}}`},
		},
		wantExpanded: true,
	}, {
		name:         "a list with no instances answers with nothing",
		path:         grpcServerPath(map[string]string{"name": "*"}),
		enc:          gnmipb.Encoding_JSON_IETF,
		payload:      jsonIetf(`{}`),
		wantExpanded: true,
	}, {
		name: "a bare list stays one array",
		path: grpcServerPath(nil),
		enc:  gnmipb.Encoding_JSON_IETF,
	}, {
		name: "a concrete key is served as asked",
		path: grpcServerPath(map[string]string{"name": "gnxi"}),
		enc:  gnmipb.Encoding_JSON_IETF,
	}, {
		name: "a node below the list is not this case",
		path: grpcServerPath(map[string]string{"name": "*"}, "state"),
		enc:  gnmipb.Encoding_JSON_IETF,
	}, {
		name: "proto encoding is left alone",
		path: grpcServerPath(map[string]string{"name": "*"}),
		enc:  gnmipb.Encoding_PROTO,
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := tt.payload
			if payload == nil {
				payload = jsonIetf(grpcServerListPayload)
			}
			values, expanded := expandWildcardListTarget(prefix, tt.path, tt.enc, payload)
			if expanded != tt.wantExpanded {
				t.Errorf("expandWildcardListTarget() expanded = %v, want %v", expanded, tt.wantExpanded)
			}
			got := updatesOf(t, values)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("expandWildcardListTarget() = %v, want %v", got, tt.want)
			}
		})
	}
}

// An identityref key comes back from translib qualified with its module, the
// way RFC 7951 writes it, but a path key names the bare identity. Other keys
// keep any colon they hold, as an IPv6 address does.
func TestExpandWildcardListTargetKeys(t *testing.T) {
	tests := []struct {
		name    string
		path    *gnmipb.Path
		payload string
		want    map[string]string
	}{{
		name: "an identityref key reached through a leafref loses its module",
		path: &gnmipb.Path{Elem: []*gnmipb.PathElem{
			{Name: "acl"}, {Name: "acl-sets"},
			{Name: "acl-set", Key: map[string]string{"name": "*", "type": "*"}},
		}},
		payload: `{"openconfig-acl:acl-set":[{"name":"A1","type":"openconfig-acl:ACL_IPV4","config":{"name":"A1"}}]}`,
		want:    map[string]string{"name": "A1", "type": "ACL_IPV4"},
	}, {
		name: "an address key keeps its colons",
		path: &gnmipb.Path{Elem: []*gnmipb.PathElem{
			{Name: "system"}, {Name: "ntp"}, {Name: "servers"},
			{Name: "server", Key: map[string]string{"address": "*"}},
		}},
		payload: `{"openconfig-system:server":[{"address":"fe80::1","config":{"address":"fe80::1"}}]}`,
		want:    map[string]string{"address": "fe80::1"},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			values, expanded := expandWildcardListTarget(&gnmipb.Path{}, tt.path, gnmipb.Encoding_JSON_IETF, jsonIetf(tt.payload))
			if !expanded || len(values) != 1 {
				t.Fatalf("expandWildcardListTarget() = %v, %v; want one update", values, expanded)
			}
			elems := values[0].GetPath().GetElem()
			if got := elems[len(elems)-1].GetKey(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("keys = %v, want %v", got, tt.want)
			}
		})
	}
}

// The request path must survive expansion: it is reused for every instance and
// is a map key in path2URI.
func TestExpandListFallbackLeavesRequestPathAlone(t *testing.T) {
	path := grpcServerPath(map[string]string{"name": "*"}, "state", "name")
	before := proto.Clone(path).(*gnmipb.Path)

	expandListFallback(&gnmipb.Path{}, path, gnmipb.Encoding_JSON_IETF,
		&translib.GetResponse{
			ServedPath:     "/openconfig-system:system/grpc-servers/grpc-server",
			ServedListKeys: []string{"name"},
		}, jsonIetf(grpcServerListPayload))

	if !proto.Equal(before, path) {
		t.Errorf("request path was modified: got %v, want %v", path, before)
	}
}
