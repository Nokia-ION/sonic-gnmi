package jtest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sync"

	"github.com/redis/go-redis/v9"
	sdcfg "github.com/sonic-net/sonic-gnmi/sonic_db_config"
)

// Shared database clients per db.
var dbClients = make(map[string]*redis.Client)
var dbMutex = &sync.Mutex{}

func getDBClient(db string) (*redis.Client, error) {
	dbMutex.Lock()
	defer dbMutex.Unlock()

	if rclient, ok := dbClients[db]; ok {
		return rclient, nil
	}

	ns, _ := sdcfg.GetDbDefaultNamespace()
	db_id, err := sdcfg.GetDbId(db, ns)
	if err != nil {
		fmt.Errorf("failed to get db %s, %v", db, err)
		return nil, err
	}

	rclient := redis.NewClient(&redis.Options{
		Network:     "unix",
		Addr:        "/var/run/redis/redis.sock",
		Password:    "", // no password set
		DB:          db_id,
		DialTimeout: 0,
	})
	if _, err := rclient.Ping(context.Background()).Result(); err != nil {
		return nil, err
	}
	dbClients[db] = rclient

	return rclient, nil
}

// Unmarshal json formated database data into map.
func loadConfig(key string, jsonData string) (map[string]interface{}, error) {
	var fvp map[string]interface{}

	err := json.Unmarshal([]byte(jsonData), &fvp)
	if err != nil {
		return nil, fmt.Errorf("Failed to Unmarshal %v err: %v", jsonData, err)
	}
	if key != "" {
		kv := map[string]interface{}{}
		kv[key] = fvp
		return kv, nil
	}
	return fvp, nil
}

// Applies data(mpi) to database.
// Assuming input data is in key field/value pair format
func loadDB(db string, mpi map[string]interface{}) error {
	rClient, err := getDBClient(db)
	if err != nil {
		return err
	}

	for key, fv := range mpi {
		switch fv.(type) {
		case map[string]interface{}:
			if _, err := rClient.HMSet(context.Background(), key, fv.(map[string]interface{})).Result(); err != nil {
				return fmt.Errorf("Invalid data for db:  %v : %v %v", key, fv, err)
			}
		default:
			return fmt.Errorf("Invalid data for db: %v : %v", key, fv)
		}
	}
	return nil
}

// Removes field or key from database.
// Fields are specified as any string array. Removes key if no field is specified.
func removeFromDB(db string, mpi map[string]interface{}) error {
	rClient, err := getDBClient(db)
	if err != nil {
		return err
	}

	for key, fv := range mpi {
		switch fv.(type) {
		case []interface{}:
			sfv := fv.([]interface{})
			if len(sfv) == 0 {
				// Empty map, the key will be removed.
				_, err = rClient.Del(context.Background(), key).Result()
			} else {
				fields := make([]string, len(sfv))
				for i, field := range sfv {
					fields[i] = field.(string)
				}
				_, err = rClient.HDel(context.Background(), key, fields...).Result()
			}
			if err != nil {
				return fmt.Errorf("Invalid data for db:  %v : %v %v", key, fv, err)
			}
		default:
			return fmt.Errorf("Invalid data for db: %v : %v, %v", key, fv, reflect.TypeOf(fv))
		}
	}
	return nil
}

// Load JSON encoded data into db. If key is specified, the supplied
// data is for key only.
func LoadConfigToDB(db string, key string, jsonVal string) error {
	mpi, err := loadConfig(key, jsonVal)
	if err != nil {
		return err
	}
	if err := loadDB(db, mpi); err != nil {
		return err
	}
	return nil
}

// Remove JSON encoded data from db. If key is specified, the supplied
// data is for key only. If a key has no field specified, the whole key
// is removed.
func RemoveConfigFromDB(db string, key string, jsonVal string) error {
	mpi, err := loadConfig(key, jsonVal)
	if err != nil {
		return err
	}
	if err := removeFromDB(db, mpi); err != nil {
		return err
	}
	return nil
}

// Reads fields from database and validates against provided JSON Schema.
func readFromDBandValidate(db string, mpi map[string]interface{}) error {
	rClient, err := getDBClient(db)
	if err != nil {
		return err
	}

	for key, fv := range mpi {
		switch fv.(type) {
		case map[string]interface{}:
			// If we are looking for a missing key, check if the table is present
			if len(fv.(map[string]interface{})) == 0 {
				if exists, err := rClient.Exists(context.Background(), key).Result(); err != nil || exists != 0 {
					return fmt.Errorf("Invalid data for %v: exists=%v, err=%v", key, exists, err)
				}
				continue
			}
			var errs []error
			for field, wantVal := range fv.(map[string]interface{}) {
				gotVal, err := rClient.HGet(context.Background(), key, field).Result()
				if err != nil {
					errs = append(errs, fmt.Errorf("Invalid data for db: key=%s field=%s err=%v", key, field, err))
				}
				if gotVal != wantVal.(string) {
					errs = append(errs, fmt.Errorf("Get values did not match for field \"%v\": gotVal (%v); wantVal (%v)", field, gotVal, wantVal))
				}
			}
			return errors.Join(errs...)
		default:
			return fmt.Errorf("Invalid data for db: %v : %v, %v", key, fv, reflect.TypeOf(fv))
		}
	}
	return nil
}

// Read JSON encoded data from db.
func ReadConfigFromDBandValidate(db string, key string, jsonVal string) error {
	mpi, err := loadConfig(key, jsonVal)
	if err != nil {
		return err
	}
	return readFromDBandValidate(db, mpi)
}
