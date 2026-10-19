package client

import (
	"testing"

	"github.com/Azure/sonic-mgmt-common/translib"
	"github.com/Workiva/go-datastructures/queue"
	spb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/openconfig/ygot/ygot"
)

func TestToPrefix_OpenConfigStripsModulePrefix(t *testing.T) {
	ts := &translSubscriber{
		client: &TranslClient{
			prefix: &spb.Path{Origin: "openconfig", Target: "dut1"},
		},
	}
	got := ts.toPrefix("/openconfig-interfaces:interfaces/interface[name=Ethernet14]")
	if got.GetOrigin() != "openconfig" {
		t.Errorf("origin: got %q, want openconfig", got.GetOrigin())
	}
	if got.GetTarget() != "dut1" {
		t.Errorf("target: got %q, want dut1", got.GetTarget())
	}
	if len(got.Elem) != 2 {
		t.Fatalf("elem len: got %d, want 2: %v", len(got.Elem), got.Elem)
	}
	if got.Elem[0].Name != "interfaces" {
		t.Errorf("elem[0].Name: got %q, want interfaces", got.Elem[0].Name)
	}
	if got.Elem[1].Name != "interface" || got.Elem[1].Key["name"] != "Ethernet14" {
		t.Errorf("elem[1]: got %+v, want interface[name=Ethernet14]", got.Elem[1])
	}
}

func TestToPrefix_EmptyOriginKeepsModulePrefix(t *testing.T) {
	ts := &translSubscriber{
		client: &TranslClient{
			prefix: &spb.Path{},
		},
	}
	got := ts.toPrefix("/openconfig-interfaces:interfaces/interface[name=Ethernet14]")
	if got.GetOrigin() != "" {
		t.Errorf("origin: got %q, want empty", got.GetOrigin())
	}
	if len(got.Elem) == 0 || got.Elem[0].Name != "openconfig-interfaces:interfaces" {
		t.Errorf("elem[0].Name: got %v, want module-prefixed name", got.Elem)
	}
}

func TestDefaultMsgBuilder_OpenConfigStripsModulePrefix(t *testing.T) {
	ts := &translSubscriber{
		client: &TranslClient{
			prefix: &spb.Path{Origin: "openconfig"},
		},
	}
	n, err := defaultMsgBuilder(&translib.SubscribeResponse{
		Path:      "/openconfig-interfaces:interfaces/interface[name=Ethernet14]",
		Timestamp: 42,
		Delete:    []string{"openconfig-if-ethernet:ethernet"},
	}, ts)
	if err != nil {
		t.Fatal(err)
	}
	if n == nil {
		t.Fatal("notification is nil")
	}
	if n.Prefix.GetOrigin() != "openconfig" {
		t.Errorf("prefix origin: got %q, want openconfig", n.Prefix.GetOrigin())
	}
	if len(n.Prefix.Elem) < 1 || n.Prefix.Elem[0].Name != "interfaces" {
		t.Errorf("prefix elems: got %v, want interfaces/...", n.Prefix.Elem)
	}
	if len(n.Delete) != 1 || n.Delete[0].Elem[0].Name != "ethernet" {
		t.Errorf("delete path: got %v, want ethernet", n.Delete)
	}
}

func TestNotify(t *testing.T) {
	tests := []struct {
		name        string
		v           *translib.SubscribeResponse
		builderMsg  *spb.Notification
		builderErr  error
		hasSuperSub bool
		expectedErr bool
		expectedLen int
	}{
		{
			name: "Standard notification path",
			v:    &translib.SubscribeResponse{},
			builderMsg: &spb.Notification{
				Update: []*spb.Update{{Path: &spb.Path{Target: "test"}}},
			},
			expectedErr: false,
			expectedLen: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 1. Initialize the Subscriber and Client pointers
			ts := &translSubscriber{}
			ts.client = &TranslClient{}

			// 2. Fix the Queue Assignment
			ts.client.q = queue.NewPriorityQueue(10, false)

			// 3. Mock the msgBuilder function
			ts.msgBuilder = func(resp *translib.SubscribeResponse, s *translSubscriber) (*spb.Notification, error) {
				return tt.builderMsg, tt.builderErr
			}

			// 4. Handle SuperSub if needed
			if tt.hasSuperSub {
				ts.client.superSub = &superSubscription{}
			}

			// Execute
			ts.notify(tt.v)
		})
	}
}
func TestNotifyNil(t *testing.T) {
	tests := []struct {
		name        string
		v           *translib.SubscribeResponse
		builderMsg  *spb.Notification
		builderErr  error
		hasSuperSub bool
		expectedErr bool
		expectedLen int
	}{
		{
			name: "Standard notification path",
			v:    &translib.SubscribeResponse{},
			builderMsg: &spb.Notification{
				Update: []*spb.Update{{Path: &spb.Path{Target: "test"}}},
			},
			expectedErr: false,
			expectedLen: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 1. Initialize the Subscriber and Client pointers
			ts := &translSubscriber{}
			ts.client = &TranslClient{}

			// 2. Fix the Queue Assignment
			ts.client.q = queue.NewPriorityQueue(10, false)

			// 3. Mock the msgBuilder function
			ts.msgBuilder = func(resp *translib.SubscribeResponse, s *translSubscriber) (*spb.Notification, error) {
				if resp == nil {
					// Return a valid notification to pass the (len == 0) check
					return &spb.Notification{
						Update: []*spb.Update{{}},
					}, nil
				}
				return nil, nil
			}

			// 4. Handle SuperSub if needed
			if tt.hasSuperSub {
				ts.client.superSub = &superSubscription{}
			}

			// Execute
			ts.notify(tt.v)
		})
	}
}

func mustPath(t *testing.T, s string) *spb.Path {
	t.Helper()
	p, err := ygot.StringToStructuredPath(s)
	if err != nil {
		t.Fatalf("bad path %q: %v", s, err)
	}
	return p
}

func pathStrings(t *testing.T, msg *spb.Notification) (updates, deletes []string) {
	t.Helper()
	for _, u := range msg.Update {
		s, _ := ygot.PathToString(u.Path)
		updates = append(updates, s)
	}
	for _, d := range msg.Delete {
		s, _ := ygot.PathToString(d)
		deletes = append(deletes, s)
	}
	return
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestFilterFanout(t *testing.T) {
	const props = "/components/component[name=Fan1]/properties"
	tests := []struct {
		name        string
		pattern     string
		prefix      string
		updates     []string
		deletes     []string
		wantUpdates []string
		wantDeletes []string
	}{{
		name:        "leaf under wildcard drops key leaf",
		pattern:     "/openconfig-platform:components/component[name=Fan1]/properties/property[name=*]/state/value",
		prefix:      props,
		updates:     []string{"/property[name=speed]/name", "/property[name=speed]/state/value"},
		deletes:     []string{"/property[name=gone]", "/property[name=gone]/name"},
		wantUpdates: []string{"/property[name=speed]/state/value"},
		wantDeletes: []string{"/property[name=gone]"},
	}, {
		name:        "pattern ends at list keeps key leaf",
		pattern:     "/openconfig-platform:components/component[name=Fan1]/properties/property[name=*]",
		prefix:      props,
		updates:     []string{"/property[name=speed]/name", "/property[name=speed]/state/value"},
		wantUpdates: []string{"/property[name=speed]/name", "/property[name=speed]/state/value"},
	}, {
		name:        "pattern names key leaf",
		pattern:     "/openconfig-platform:components/component[name=Fan1]/properties/property[name=*]/name",
		prefix:      props,
		updates:     []string{"/property[name=speed]/name", "/property[name=speed]/state/value"},
		wantUpdates: []string{"/property[name=speed]/name"},
	}, {
		name:        "two wildcards with module prefixed response",
		pattern:     "/openconfig-platform:components/component[name=*]/properties/property[name=*]/state/value",
		prefix:      "/openconfig-platform:components/component[name=Fan1]/properties",
		updates:     []string{"/property[name=speed]/name", "/property[name=speed]/state/value"},
		wantUpdates: []string{"/property[name=speed]/state/value"},
	}, {
		name:        "replace below a shortened prefix",
		pattern:     "/openconfig-platform:components/component[name=Fan1]/properties/property[name=*]/state/value",
		prefix:      "/components/component[name=Fan1]",
		updates:     []string{"/properties/property[name=speed]/name", "/properties/property[name=speed]/state/value"},
		deletes:     []string{"/properties"},
		wantUpdates: []string{"/properties/property[name=speed]/state/value"},
		wantDeletes: []string{"/properties"},
	}, {
		name:        "sample delete from root prefix",
		pattern:     "/openconfig-platform:components/component[name=*]/properties/property[name=*]/state/value",
		prefix:      "/",
		deletes:     []string{"/components/component[name=Fan1]/properties", "/components/component[name=Fan1]/name"},
		wantDeletes: []string{"/components/component[name=Fan1]/properties"},
	}, {
		name:        "prefix below the wildcards is left alone",
		pattern:     "/openconfig-interfaces:interfaces/interface[name=*]/state",
		prefix:      "/interfaces/interface[name=Ethernet0]/state",
		updates:     []string{"/oper-status", "/admin-status"},
		wantUpdates: []string{"/oper-status", "/admin-status"},
	}, {
		name:        "other component is not filtered",
		pattern:     "/openconfig-platform:components/component[name=Fan1]/properties/property[name=*]/state/value",
		prefix:      "/components/component[name=Fan2]/properties",
		updates:     []string{"/property[name=speed]/name"},
		wantUpdates: []string{"/property[name=speed]/name"},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := &translSubscriber{}
			ts.setPatterns([]string{tt.pattern})
			msg := &spb.Notification{Prefix: mustPath(t, tt.prefix)}
			for _, u := range tt.updates {
				msg.Update = append(msg.Update, &spb.Update{Path: mustPath(t, u)})
			}
			for _, d := range tt.deletes {
				msg.Delete = append(msg.Delete, mustPath(t, d))
			}
			ts.filterFanout(msg)
			gotU, gotD := pathStrings(t, msg)
			if !sameStrings(gotU, tt.wantUpdates) {
				t.Errorf("updates: got %v, want %v", gotU, tt.wantUpdates)
			}
			if !sameStrings(gotD, tt.wantDeletes) {
				t.Errorf("deletes: got %v, want %v", gotD, tt.wantDeletes)
			}
		})
	}
}
