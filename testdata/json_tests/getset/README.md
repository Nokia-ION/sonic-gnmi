# gNMI JSON getset tests — running off-box

This directory holds **data-driven gNMI get/set test cases** for the `jsontest`
framework. Each `*.json` file describes one or more gNMI operations plus a
[JSON Schema](https://json-schema.org/) that the response must satisfy.

"Off-box" means the tests run on a **development machine / build container** — no
switch, ASIC, `swss` or `syncd` required. The harness spins up an in-process gNMI
server backed by translib, and a plain local `redis` instance acts as the
"virtual DB" (seeded from `../config_db.txt`).

---

## 1. What runs the tests

| Piece | Path | Role |
|-------|------|------|
| Test harness | `gnmi_server/jsontest_harness_test.go` (`TestGnmiJsonGetSet`) | globs `getset/*.json` and feeds each to the framework |
| Framework engine | `jsontest/*.go` | parses the JSON, issues the gNMI op, validates the response against the embedded JSON Schema |
| Off-box runner | `tools/test/run-jsontest.sh` | starts redis, generates the env, loads YANG models, runs the harness |
| Fixture | `testdata/json_tests/config_db.txt` | seeds `CONFIG_DB` before **each** test file (flushed + reloaded every time) |

---

## 2. Prerequisites

Run inside a **`sonic-slave-trixie`** build container (it has `go`, `redis`, and
the CGO deps: `libswsscommon`, `libyang`, `hiredis`). You also need:

- `sonic-mgmt-common` built far enough that `build/yang/` exists (the YANG models).
- `sonic-gnmi` vendored (`make go-deps`, i.e. `go mod vendor` + vendor patches).

A typical container is started once and reused (here named `jsontest-runner`),
with the host repo mounted at `/sonic`.

---

## 3. Run the tests

From the `sonic-gnmi` root inside the container:

```bash
# run EVERY case in getset/
bash tools/test/run-jsontest.sh

# run a SINGLE case
bash tools/test/run-jsontest.sh oc_intf_mtu_roundtrip.json

# equivalently, target via env var (glob allowed)
JSON_TGT='oc_*.json' bash tools/test/run-jsontest.sh
```

From the host, driving the container directly:

```bash
docker exec jsontest-runner bash -lc '
  cd /sonic/src/sonic-gnmi
  export GOPATH=/tmp/go GOSUMDB=off
  bash tools/test/run-jsontest.sh oc_intf_mtu_roundtrip.json'
```

A pass looks like:

```
--- PASS: TestGnmiJsonGetSet/... (0.02s)
PASS
ok  github.com/sonic-net/sonic-gnmi/gnmi_server
```

> **Tip — cut the noise.** The run prints cgo warnings and glog lines. Filter to
> the verdict:
> ```bash
> ... run-jsontest.sh 2>&1 | grep -E 'jtest.go|operation.go|^ *- |RUN|PASS|FAIL|Invalid JSON'
> ```

---

## 4. The virtual DB (fixture)

Response fields only appear if the row exists in the DB. Add what your test needs
to `../config_db.txt`, using the native SONiC `TABLE|key` form and the DB field
names:

```json
{
  "PORT|Ethernet0": { "alias": "Eth0", "lanes": "0,1,2,3", "speed": "100000", "mtu": "9100", "admin_status": "up" }
}
```

The fixture is **shared** by all getset files and re-seeded before each one, so a
test can rely only on what is in `config_db.txt` (not on side effects of other
tests). It currently seeds a single `Ethernet0` port; add more `TABLE|key` rows
here as new tests need them.

---

## 5. Test file format

```json
{
  "title": "human readable name",
  "operations": [
    {
      "operation": "get",                     // get | set | subscribe
      "returnCode": 0,                        // expected gRPC code (0 = OK)
      "xpath": "/openconfig-interfaces:interfaces/interface[name=Ethernet0]",
      "target": "OC_YANG",

      "type": "object",                       // <-- from here down is JSON Schema
      "required": ["openconfig-interfaces:interface"],
      "properties": { "...": "..." }
    }
  ]
}
```

- **`operations` must be an array** — a top-level `operation` object alone loads
  nothing and the test passes vacuously.
- The first xpath segment is namespace-qualified (`module:container`); deeper
  segments are bare names.
- Everything from `type` downward is standard **JSON Schema draft-07** applied to
  the response body.

### Mapping YANG → schema

| YANG | Response / schema |
|------|-------------------|
| top node | key carries `module:` prefix (e.g. `openconfig-interfaces:config`) |
| `container` | `"type": "object"` |
| `list` | `"type": "array"` of objects |
| `leaf` (string/enum/…) | `"type": "string"` |
| `leaf` (uint/int) | `"type": "integer"` (translib emits numbers, not strings) |
| `leaf` (boolean) | `"type": "boolean"` |

### Make the check actually bite

`properties` alone asserts almost nothing. To detect regressions:

- put fields in **`required`** (missing field fails),
- pin values with **`enum`**/`const` (wrong value fails),
- add **`"additionalProperties": false`** to catch unexpected/renamed keys.

Verify a test *can* fail: temporarily break an `enum` value, confirm `FAIL` with a
`- ... must be one of ...` line, then revert.

---

## 6. Writing a new test (dump-first)

Rather than hand-predicting the response, write a throwaway dump op (no schema),
run it, and copy the printed body:

```json
{ "operations": [ { "operation": "get", "returnCode": 0,
  "xpath": "/sonic-vlan:sonic-vlan/VLAN", "target": "OC_YANG",
  "type": "string" } ] }
```

The run prints `Invalid JSON Response: {…}` — that `{…}` is the exact response.
Flesh it out into `required`/`properties`/`enum`, then delete the dump file.

---

## 7. Reading failures

The prefix of the failing log line tells you the class:

| Marker | Meaning | Fix |
|--------|---------|-----|
| `jtest.go:...: Error loading json file ...` | the test file is **malformed JSON** | `jq . <file>` / `python3 -m json.tool <file>` gives the line/column |
| `operation.go:...: got return code X, want OK` | wrong gRPC code (bad xpath, unsupported/unpopulated model, missing fixture) | check xpath + fixture |
| `operation.go:...: The response JSON is not valid` preceded by `- <path>: <reason>` | **schema mismatch** | each `- ` line names the offending path + reason; diff against the printed `Invalid JSON Response` |

---

## 8. Model support off-box

The off-box runner regenerates the transformer `models_list` so the **same
OpenConfig models the switch serves** are loaded (interfaces, platform, lacp,
system, qos, acl, plus all `sonic-*`). Without that fix, only `sonic-*` models
load and every `openconfig-*` path returns
`NotFound: No entry found in xYangSpecMap`.

The runner also generates the **CVL schema** (`build/cvl/schema/*.yin`, via
`cvl/tools/generate_yin.py`). This is what makes `set`/`update`/`delete`
**persist** off-box: translib's write path orders tables to write through
`cvl.SortDepTables()`, which needs the compiled schema. If the directory is empty
(the off-box default), `SortDepTables()` returns an empty table list *with no
error*, so translib silently skips every write — the gNMI `Set` returns OK
(`returnCode 0`) but nothing is committed, and `set`→`get` round-trips fail.
With the schema present, writes commit to the virtual DB.

Caveats:

- `set`/`update`/`delete` work off-box, so `set`→`get` round-trips are supported.
  Because the fixture is re-seeded before **each file** (not each operation),
  put the `set` and the follow-up `get` in the **same file's** `operations`
  array (see `oc_intf_mtu_roundtrip.json`).
- Some paths **resolve but return empty** because translib has no backend for
  them (e.g. `openconfig-platform` `components/component/properties/property/state/value`).
  That is a translib gap, not a framework/model-loading issue.

---

## 9. Current examples

| File | Model | Demonstrates |
|------|-------|--------------|
| `oc_intf_mtu_roundtrip.json` | `openconfig-interfaces` | `set`→`get` round trip: update `Ethernet0` MTU, then read it back and pin the value with `enum` |
