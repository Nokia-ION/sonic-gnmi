package jtest

// jsontest.go: A json based GNMI component test library

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/xeipuuv/gojsonschema"
	"golang.org/x/net/context"
)

// context keys for RunTest
const (
	CtxIDGChannel      string = "gnmi_grpc_channel"
	CtxIDSubscribeSess string = "gnmi_subscribe_sess"
)

const (
	SchemaIDGDef string = "globalDef"
)

// JSONFilter is a callbak hook for customizing json data
type JSONFilter func(map[string]interface{})

type UnitTest struct {
	desc       string
	operations []Operation
}

func loadJsonFromFile(t *testing.T, filename string) (map[string]interface{}, error) {
	/* Load and parse the json file */
	schema := gojsonschema.NewReferenceLoader("file://./" + filename)
	schemaJsonIf, err := schema.LoadJSON()
	if err != nil {
		t.Fatalf("Error loading json file \"%s\": %v", filename, err)
		return nil, err
	}
	schemaJson := schemaJsonIf.(map[string]interface{})
	return schemaJson, nil
}

func UnitTestFromFile(t *testing.T, ctx context.Context, filename string, hook JSONFilter) (UnitTest, error) {
	var st UnitTest

	schemaJson, err := loadJsonFromFile(t, filename)
	if err != nil {
		return st, err
	}

	/* Add the source filename to the test description */
	splitFilename := strings.Split(filename, "/")
	baseFilename := splitFilename[len(splitFilename)-1]
	basePath := strings.Join(splitFilename[:len(splitFilename)-1], "/")
	if val, ok := schemaJson["title"]; ok {
		st.desc = val.(string)
	}
	st.desc = st.desc + " (" + baseFilename + ")"

	/* Extract the "globalDef" section so it can be included in each case
	 * (operation) the file runs. */
	globalDefs, _ := schemaJson[SchemaIDGDef]

	/* Load any requested include files and add them to the global definitions. */
	includeDefs, hasIncludes := schemaJson["includeDefs"]
	if hasIncludes {
		for _, include := range includeDefs.([]interface{}) {
			incFilename := basePath + "/" + include.(string)
			incJson, err := loadJsonFromFile(t, incFilename)
			if err != nil {
				return st, err
			}
			incDefGlobal, _ := incJson[SchemaIDGDef]
			if incDefGlobal == nil || len(incDefGlobal.(map[string]interface{})) == 0 {
				t.Errorf("Missing defs in include file %v", include.(string))
			}
			for k, v := range incDefGlobal.(map[string]interface{}) {
				if globalDefs == nil {
					globalDefs = make(map[string]interface{})
				}
				if _, exists := globalDefs.(map[string]interface{})[k]; exists {
					t.Fatalf("Error parsing %s: inculde file %s would overwrite existing definition %s", baseFilename, include.(string), k)
				}
				globalDefs.(map[string]interface{})[k] = v
			}
		}
	}

	if val, ok := schemaJson["operations"]; ok {
		for _, opp := range val.([]interface{}) {

			op := opp.(map[string]interface{})
			if hook != nil {
				hook(op)
			}
			// Add global definitions to the mp.
			op[SchemaIDGDef] = globalDefs
			new_op, err := NewOperation(ctx, op)
			if err != nil {
				return st, fmt.Errorf("Error when parsing operation for test %v\n%v", filename, err)
			}
			st.operations = append(st.operations, new_op)
		}
	}

	return st, nil
}

func RunTest(t *testing.T, ctx context.Context, jut *UnitTest) {
	t.Run(jut.desc, func(t *testing.T) {
		for _, op := range jut.operations {
			t.Logf("operation: %v", op.Desc())
			op.Execute(t, ctx)
		}
	})
}

func LoadFileToDB(db string, key string, filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("Failed to read file '%s'; err=%v", filePath, err)
	}

	if err = LoadConfigToDB(db, key, string(data)); err != nil {
		return fmt.Errorf("Failed to load config:%v", err)
	}
	return nil
}

func JsonIETFValidation(jsonietf []byte, schema string) error {
	docLoader := gojsonschema.NewStringLoader(string(jsonietf))
	result, err := gojsonschema.Validate(gojsonschema.NewBytesLoader([]byte(schema)), docLoader)
	if err != nil {
		return fmt.Errorf("Error in validating jsonietf for schema %v. err: %v", schema, err)
	}
	if !result.Valid() {
		return fmt.Errorf("Failed to validate jsonietf for schema %v", schema)
	}
	return nil
}
