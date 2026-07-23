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
| One-command driver | `tools/jsontest-offbox.sh` | **from the host**: provisions (or reuses) a slave container, installs deps, builds, then runs a case |
| Off-box runner | `tools/test/run-jsontest.sh` | **inside the container**: starts redis, generates the env, self-heals YANG `models_list` + CVL schema, runs the harness |
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

### Easiest: one command from the host

`tools/jsontest-offbox.sh` does everything — finds the `sonic-slave-trixie`
image, provisions a persistent container (`jsontest-runner`), installs the
SONiC-built CGO deps + redis, builds `sonic-gnmi`, then runs the case. Run it
from the repo root (requires a prior full build so `target/debs/trixie/*.deb`
and `build/yang` exist):

```bash
# run a single case (default is oc_intf_mtu_roundtrip.json)
src/sonic-gnmi/tools/jsontest-offbox.sh cpn_lacp_getset.json

# run every case in getset/
src/sonic-gnmi/tools/jsontest-offbox.sh '*.json'

# force a fresh container (re-install deps + rebuild)
FORCE_REBUILD=1 src/sonic-gnmi/tools/jsontest-offbox.sh oc_intf_mtu_roundtrip.json
```

The **first** run provisions (a few minutes); **subsequent** runs reuse the
existing container and jump straight to the test (seconds). Delete the container
with `docker rm -f jsontest-runner` to start over.

### Inside the container

From the `sonic-gnmi` root inside the container:

```bash
# run EVERY case in getset/
bash tools/test/run-jsontest.sh

# run a SINGLE case
bash tools/test/run-jsontest.sh oc_intf_mtu_roundtrip.json

# equivalently, target via env var (glob allowed)
JSON_TGT='oc_*.json' bash tools/test/run-jsontest.sh
```

Or drive that from the host directly:

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
  "PORT|Ethernet0":            { "alias": "Eth0", "lanes": "0,1,2,3", "speed": "100000", "mtu": "9100", "admin_status": "up" },
  "PORTCHANNEL|PortChannel1":  { "admin_status": "up", "mtu": "9100", "lacp_key": "auto", "min_links": "1" }
}
```

The fixture is **shared** by all getset files and re-seeded before each one, so a
test can rely only on what is in `config_db.txt` (not on side effects of other
tests). It currently seeds an `Ethernet0` port and a `PortChannel1`; add more
`TABLE|key` rows here as new tests need them.

> **Only `CONFIG_DB` is seeded from the fixture.** `STATE_DB`/`APPL_DB` (and any
> other DB) are **not** flushed or seeded by the harness. Operational data a live
> switch would have (e.g. LLDP neighbors in `APPL_DB`, `LAG_TABLE`/
> `LAG_MEMBER_TABLE` in `STATE_DB` created by `teamd`) must be seeded **inside the
> test** with a `dbHSet` sub-operation — see §5.1. Because those DBs are not
> re-flushed between files, prefer self-contained sub-op seeding over relying on
> leftovers.

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

### 5.1 DB sub-operations (seed / validate other DBs)

An operation may carry a `subOpers` array that touches Redis **directly**, before
(seed) and after (validate) the gNMI op. This is how a test provides operational
state the fixture can't (it only seeds `CONFIG_DB`) and how it proves a `set`
actually persisted.

```json
{
  "operation": "get",
  "returnCode": 0,
  "xpath": "/openconfig-lacp:lacp/interfaces/interface[name=PortChannel1]/config/fallback",
  "target": "OC_YANG",
  "type": "object", "required": ["openconfig-lacp:fallback"],
  "properties": { "openconfig-lacp:fallback": { "type": "boolean", "enum": [false] } },
  "subOpers": [
    {
      "oper": "dbHSet",                                  // seed operational STATE_DB (teamd would)
      "db": "STATE_DB",
      "value": {
        "LAG_TABLE|PortChannel1":               { "oper_status": "up" },
        "LAG_MEMBER_TABLE|PortChannel1|Ethernet0": { "status": "enabled" }
      }
    }
  ]
}
```

| `oper` | Effect |
|--------|--------|
| `dbHSet` | `HSET` each `TABLE|key` → `{field: value}` into `db` (seed) |
| `dbHDel` | delete the listed fields/keys from `db` |
| `dbHGetValidate` | read `TABLE|key` back from `db` and **fail** if any field ≠ expected — use it to prove a gNMI `set` committed the right DB fields |
| `dbLoad` | bulk-load a JSON blob into `db` |

`db` is one of `CONFIG_DB`, `APPL_DB`, `STATE_DB`, … A `dbHGetValidate` against
`CONFIG_DB` after a `set` is the strongest persistence check (see
`cpn_lacp_getset.json`).

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
- **Writes verify parent-table existence.** translib's write path checks that the
  parent objects exist (for subtree models, via the model's *Subscribe*
  transformer). If the transformer lists operational tables a live switch would
  have (e.g. LACP needs `STATE_DB LAG_TABLE` **and** `LAG_MEMBER_TABLE|<pc>|*`),
  the write returns `Unknown: Resource not found` off-box until you seed them with
  a `dbHSet` sub-op. `cpn_lacp_getset.json` shows the pattern.
- **Writes are CVL-validated.** A `set` only persists if the target DB field
  exists in the SONiC YANG that CVL compiled (`sonic-*.yang` from
  `src/sonic-yang-models/`). If a transformer maps an OpenConfig leaf to a DB
  field the model doesn't define, CVL rejects it
  (`CVL Failure ... Unknown field "<x>"`). This is a real model/transformer gap,
  not an off-box artifact — e.g. openconfig-lacp `system-id-mac`/`system-priority`/
  `lacp-mode` map to `system_id`/`system_priority`/`active`, none of which exist in
  `sonic-portchannel.yang` (which has `system_mac`, `fallback`, `fast_rate`), so
  only `interval` and `fallback` writes persist.
- Some paths **resolve but return empty** because translib has no backend for
  them (e.g. `openconfig-platform` `components/component/properties/property/state/value`).
  That is a translib gap, not a framework/model-loading issue.

---

## 9. Current examples

| File | Model | Demonstrates |
|------|-------|--------------|
| `oc_intf_mtu_roundtrip.json` | `openconfig-interfaces` | `set`→`get` round trip: update `Ethernet0` MTU, then read it back and pin the value with `enum` |
| `oc_lldp_neighbor_get.json` | `openconfig-lldp` | seed `APPL_DB LLDP_ENTRY_TABLE` with a `dbHSet` sub-op, then `get` neighbor `system-name`/`chassis-id` and pin the values |
| `cpn_lacp_getset.json` | `openconfig-lacp` | full get/**set**: seed operational `STATE_DB` LAG tables, `update` the LACP `config` (`interval`+`fallback`), read it back, and prove persistence with a `dbHGetValidate` against `CONFIG_DB PORTCHANNEL` |
| `lacp_fallback_mode.json` | `openconfig-lacp` | borrowed from UMF and adapted to CPN (path convention + fixtures): read-only fallback default-value checks. See its `_comment` for the UMF→CPN deltas |
