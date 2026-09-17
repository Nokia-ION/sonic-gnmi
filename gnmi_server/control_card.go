package gnmi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	log "github.com/golang/glog"
	common_pb "github.com/openconfig/attestz/proto/common_definitions"
	"github.com/redis/go-redis/v9"
	"github.com/sonic-net/sonic-gnmi/common_utils"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// inventoryPath describes the control cards of a modular chassis. It is a var so
// tests can point it elsewhere.
var inventoryPath = "/run/inventory.json"

const (
	// syseepromd publishes each ONIE TLV of the chassis EEPROM to STATE_DB under
	// EEPROM_INFO|<tlv code>, with the decoded contents in the "Value" field.
	eepromPartNumberKey   = "EEPROM_INFO|0x22"
	eepromSerialNumberKey = "EEPROM_INFO|0x23"
	eepromVendorNameKey   = "EEPROM_INFO|0x2d"
	eepromValueField      = "Value"

	// Slot reported for the single control card of a fixed form factor chassis.
	fixedChassisSlotID = "1"
)

type inventoryFile struct {
	Manufacturer string `json:"manufacturer"`
	Part         string `json:"part_number"`
	Serial       string `json:"chassis_serial_number"`
	ControlCards []struct {
		SerialNumber string `json:"serial_number"`
		SlotID       string `json:"slot_id"`
	} `json:"control_cards"`
}

type controlCardInfo struct {
	role   common_pb.ControlCardRole
	serial string // serial number of the control card itself
	slot   string
	// Identity of the chassis the control card is installed in.
	manufacturer string
	partNumber   string
	serialNumber string
}

type chassisInfo struct {
	manufacturer string
	partNumber   string
	serialNumber string
}

// makeControlCardVendorId assembles a ControlCardVendorId proto from stored control card
// and chassis info.
func makeControlCardVendorId(c *controlCardInfo) (*common_pb.ControlCardVendorId, error) {
	if c == nil {
		return nil, fmt.Errorf("control card info unavailable")
	}

	return &common_pb.ControlCardVendorId{
		ControlCardRole:     c.role,
		ControlCardSerial:   c.serial,
		ControlCardSlot:     c.slot,
		ChassisManufacturer: c.manufacturer,
		ChassisPartNumber:   c.partNumber,
		ChassisSerialNumber: c.serialNumber,
	}, nil
}

// loadControlCardInfo reads the control card identity reported by enrollz and
// attestz. A modular chassis enumerates its supervisors in the inventory file,
// which takes precedence when present. A fixed form factor box such as the 7215
// IXS-A1 has no inventory file, so its chassis EEPROM is used instead and the
// chassis is reported as the one active control card. The bool reports whether
// the identity came from the inventory, which is the authoritative source.
func loadControlCardInfo() ([]*controlCardInfo, bool, error) {
	cards, err := loadControlCardInfoFromInventory()
	if err == nil {
		return cards, true, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, err
	}
	cards, dbErr := loadControlCardInfoFromStateDB()
	if dbErr != nil {
		return nil, false, fmt.Errorf("no inventory at %s, and reading the chassis EEPROM failed with: %w", inventoryPath, dbErr)
	}
	return cards, false, nil
}

// loadControlCardInfoFromInventory reads control card identity from the inventory JSON file.
func loadControlCardInfoFromInventory() ([]*controlCardInfo, error) {
	data, err := os.ReadFile(inventoryPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read inventory file with: %w", err)
	}
	var inv inventoryFile
	if err := json.Unmarshal(data, &inv); err != nil {
		return nil, fmt.Errorf("failed to unmarshal inventory info with: %w", err)
	}
	if len(inv.ControlCards) == 0 {
		return nil, fmt.Errorf("found no control cards in %s", inventoryPath)
	}

	card := inv.ControlCards[0]
	return []*controlCardInfo{{
		role:         common_pb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE,
		serial:       card.SerialNumber,
		slot:         card.SlotID,
		manufacturer: inv.Manufacturer,
		partNumber:   inv.Part,
		serialNumber: inv.Serial,
	}}, nil
}

// loadControlCardInfoFromStateDB reports the chassis of a fixed form factor
// device as its single active control card.
func loadControlCardInfoFromStateDB() ([]*controlCardInfo, error) {
	chassis, err := loadChassisInfo()
	if err != nil {
		return nil, err
	}
	return []*controlCardInfo{{
		role:         common_pb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE,
		serial:       chassis.serialNumber,
		slot:         fixedChassisSlotID,
		manufacturer: chassis.manufacturer,
		partNumber:   chassis.partNumber,
		serialNumber: chassis.serialNumber,
	}}, nil
}

// loadChassisInfo reads chassis identity from the EEPROM TLVs in STATE_DB.
func loadChassisInfo() (*chassisInfo, error) {
	client, err := common_utils.GetRedisDBClient()
	if err != nil {
		return nil, fmt.Errorf("STATE_DB connect: %w", err)
	}
	defer client.Close()

	ctx := context.Background()
	partNumber, err := client.HGet(ctx, eepromPartNumberKey, eepromValueField).Result()
	if err != nil {
		return nil, fmt.Errorf("STATE_DB %s: %w", eepromPartNumberKey, err)
	}
	serialNumber, err := client.HGet(ctx, eepromSerialNumberKey, eepromValueField).Result()
	if err != nil {
		return nil, fmt.Errorf("STATE_DB %s: %w", eepromSerialNumberKey, err)
	}
	// Vendor Name is an optional TLV.
	manufacturer, err := client.HGet(ctx, eepromVendorNameKey, eepromValueField).Result()
	if errors.Is(err, redis.Nil) {
		manufacturer = ""
	} else if err != nil {
		return nil, fmt.Errorf("STATE_DB %s: %w", eepromVendorNameKey, err)
	}

	return &chassisInfo{
		manufacturer: manufacturer,
		partNumber:   partNumber,
		serialNumber: serialNumber,
	}, nil
}

// controlCards returns the control card identity, loading it on first use.
// syseepromd may not have populated STATE_DB by the time telemetry starts, so a
// load failure is not terminal; the next RPC retries.
//
// Only an inventory-derived identity is cached for good. The chassis EEPROM is
// a fallback for boxes that have no inventory file at all, so an identity
// derived from it stays provisional and later calls keep checking whether the
// inventory has since appeared; otherwise a modular chassis whose inventory is
// written after the first RPC would report the chassis as its only control card
// forever.
func (s *Server) controlCards() ([]*controlCardInfo, error) {
	s.controlCardsMu.Lock()
	defer s.controlCardsMu.Unlock()

	if s.cachedFromInventory {
		return s.cachedControlCards, nil
	}

	hadCache := len(s.cachedControlCards) > 0
	cards, fromInventory, err := loadControlCardInfo()
	if err != nil {
		if hadCache {
			// Keep serving the identity that already worked rather than
			// failing an RPC because a reload happened to fail.
			return s.cachedControlCards, nil
		}
		return nil, status.Errorf(codes.Unavailable, "control card identity unavailable: %v", err)
	}
	if !hadCache || fromInventory {
		for _, c := range cards {
			log.V(1).Infof("Loaded control card: role=%v serial=%q slot=%q chassis=%q/%q/%q",
				c.role, c.serial, c.slot, c.manufacturer, c.partNumber, c.serialNumber)
		}
	}
	s.cachedControlCards = cards
	s.cachedFromInventory = fromInventory
	return cards, nil
}

// resolveControlCard returns the control card from cards that matches sel.
func resolveControlCard(sel *common_pb.ControlCardSelection, cards []*controlCardInfo) (*controlCardInfo, error) {
	if sel == nil || sel.GetControlCardId() == nil {
		return nil, status.Errorf(codes.InvalidArgument, "control_card_selection must be specified")
	}
	for _, card := range cards {
		switch id := sel.GetControlCardId().(type) {
		case *common_pb.ControlCardSelection_Role:
			if card.role == id.Role {
				return card, nil
			}
		case *common_pb.ControlCardSelection_Serial:
			if card.serial == id.Serial {
				return card, nil
			}
		case *common_pb.ControlCardSelection_Slot:
			if card.slot == id.Slot {
				return card, nil
			}
		}
	}
	return nil, status.Errorf(codes.InvalidArgument, "no control card matches selection: %v", sel)
}
