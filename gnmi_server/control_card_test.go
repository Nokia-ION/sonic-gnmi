package gnmi

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/agiledragon/gomonkey/v2"
	common_pb "github.com/openconfig/attestz/proto/common_definitions"
)

// useTestInventory points inventoryPath at a temp file holding contents and
// restores the original path when the test ends.
func useTestInventory(t *testing.T, contents string) string {
	t.Helper()
	testPath := filepath.Join(t.TempDir(), "inventory.json")
	if err := os.WriteFile(testPath, []byte(contents), 0644); err != nil {
		t.Fatalf("failed to write test inventory file: %v", err)
	}
	origPath := inventoryPath
	inventoryPath = testPath
	t.Cleanup(func() { inventoryPath = origPath })
	return testPath
}

func TestLoadControlCardInfo_FromInventory(t *testing.T) {
	useTestInventory(t, `{
		"manufacturer": "Acme",
		"part_number": "PN-12345",
		"chassis_serial_number": "SN-98765",
		"control_cards": [
			{
				"serial_number": "CARD-SN-001",
				"slot_id": "slot-1"
			}
		]
	}`)

	cards, fromInventory, err := loadControlCardInfo()
	if err != nil {
		t.Fatalf("loadControlCardInfo returned unexpected error: %v", err)
	}
	if !fromInventory {
		t.Error("loadControlCardInfo should report the inventory as the source")
	}
	if len(cards) != 1 {
		t.Fatalf("loadControlCardInfo returned %d cards, want 1", len(cards))
	}
	want := &controlCardInfo{
		role:         common_pb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE,
		serial:       "CARD-SN-001",
		slot:         "slot-1",
		manufacturer: "Acme",
		partNumber:   "PN-12345",
		serialNumber: "SN-98765",
	}
	if *cards[0] != *want {
		t.Errorf("control card: got %+v, want %+v", *cards[0], *want)
	}
}

func TestLoadControlCardInfo_MalformedInventory(t *testing.T) {
	useTestInventory(t, "not json")

	// A present but unusable inventory file is an error rather than a silent
	// fallback to the chassis EEPROM.
	if _, _, err := loadControlCardInfo(); err == nil {
		t.Fatal("loadControlCardInfo should fail on a malformed inventory file")
	}
}

func TestLoadControlCardInfo_NoControlCardsInInventory(t *testing.T) {
	useTestInventory(t, `{"manufacturer": "Acme", "control_cards": []}`)

	if _, _, err := loadControlCardInfo(); err == nil {
		t.Fatal("loadControlCardInfo should fail when the inventory lists no control cards")
	}
}

func TestControlCards_CachesFirstLoad(t *testing.T) {
	path := useTestInventory(t, `{
		"manufacturer": "Acme",
		"part_number": "PN-12345",
		"chassis_serial_number": "SN-98765",
		"control_cards": [{"serial_number": "CARD-SN-001", "slot_id": "slot-1"}]
	}`)

	srv := &Server{}
	first, err := srv.controlCards()
	if err != nil {
		t.Fatalf("controlCards returned unexpected error: %v", err)
	}

	// Removing the source makes a second load impossible, so a successful second
	// call proves the identity was cached.
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove inventory: %v", err)
	}
	second, err := srv.controlCards()
	if err != nil {
		t.Fatalf("controlCards returned unexpected error on cached call: %v", err)
	}
	if &first[0] != &second[0] {
		t.Error("controlCards should return the cached slice on the second call")
	}
}

func TestControlCards_ChassisFallbackUpgradesToInventory(t *testing.T) {
	// No inventory file yet, so the identity comes from the chassis EEPROM.
	missing := filepath.Join(t.TempDir(), "inventory.json")
	origPath := inventoryPath
	inventoryPath = missing
	t.Cleanup(func() { inventoryPath = origPath })

	patchStateDB := gomonkey.ApplyFunc(loadControlCardInfoFromStateDB, func() ([]*controlCardInfo, error) {
		return []*controlCardInfo{{
			role:         common_pb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE,
			serial:       "CHASSIS-SN",
			slot:         fixedChassisSlotID,
			serialNumber: "CHASSIS-SN",
		}}, nil
	})
	defer patchStateDB.Reset()

	srv := &Server{}
	cards, err := srv.controlCards()
	if err != nil {
		t.Fatalf("controlCards returned unexpected error: %v", err)
	}
	if cards[0].serial != "CHASSIS-SN" {
		t.Fatalf("first call: got serial %q, want the chassis EEPROM identity", cards[0].serial)
	}

	// The inventory shows up later, as it would on a modular chassis whose
	// inventory is written after telemetry starts serving.
	if err := os.WriteFile(missing, []byte(`{
		"manufacturer": "Acme",
		"control_cards": [{"serial_number": "CARD-SN-001", "slot_id": "slot-1"}]
	}`), 0644); err != nil {
		t.Fatalf("write inventory: %v", err)
	}

	cards, err = srv.controlCards()
	if err != nil {
		t.Fatalf("controlCards returned unexpected error after inventory appeared: %v", err)
	}
	if cards[0].serial != "CARD-SN-001" {
		t.Errorf("chassis EEPROM identity was cached for good: got serial %q, want %q",
			cards[0].serial, "CARD-SN-001")
	}
}
