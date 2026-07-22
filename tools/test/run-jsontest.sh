#!/usr/bin/env bash
#
# run-jsontest.sh: Run the JSON based gNMI component tests (jsontest) off-box
# against a local redis instance that stands in for the SONiC databases
# (a "virtual DB"). No switch, ASIC, swss or syncd are required.
#
# Prerequisites (already satisfied inside a sonic-slave-* build container):
#   - redis-server, go, and the CGO deps (libswsscommon, libyang, hiredis)
#   - sonic-mgmt-common built (build/yang present) so YANG models are available
#   - sonic-gnmi vendored (make go-deps) and vendor patches applied
#
# Usage:
#   tools/test/run-jsontest.sh [JSON_TGT]
# Examples:
#   tools/test/run-jsontest.sh                      # run every getset/*.json case
#   tools/test/run-jsontest.sh port_ethernet0.json  # run a single case file

set -e

TOPDIR=$(realpath "$(dirname "${BASH_SOURCE}")/../..")
cd "${TOPDIR}"

JSON_TGT="${1:-${JSON_TGT:-*.json}}"
REDIS_SOCK="/var/run/redis/redis.sock"

# 1. Bring up the virtual DB (a plain redis) if it is not already running.
if ! redis-cli -s "${REDIS_SOCK}" ping >/dev/null 2>&1; then
    echo "==== Starting redis-server on ${REDIS_SOCK}"
    mkdir -p /var/run/redis
    redis-server --unixsocket "${REDIS_SOCK}" --unixsocketperm 777 \
        --port 6379 --daemonize yes
    sleep 1
    redis-cli -s "${REDIS_SOCK}" ping
fi

# 2. Generate the off-box environment (DB_CONFIG_PATH, YANG_MODELS_PATH, CVL_*).
echo "==== Generating test environment"
eval "$(tools/test/env.sh | sed 's/^/export /')"

# 2b. Ensure the transformer models_list loads the OpenConfig models.
#
# sonic-mgmt-common/tools/test/env.sh symlinks
#   ${YANG_MODELS_PATH}/models_list -> sonic-mgmt-common/build/transformer/models_list
# which only exists after a *full* mgmt-common build. Off-box (with just build/yang
# present) that link dangles, so translib's getModelsList() silently loads only the
# sonic-*.yang defaults and every openconfig-* path returns
# "NotFound: No entry found in xYangSpecMap" (only openconfig-acl works, via its
# dedicated app). Regenerate a real models_list here -- the source list plus the
# sonic dependency exclusions -- so OpenConfig models (interfaces, platform, lacp,
# system, qos, ...) load exactly like they do in the on-switch gnmi container.
MGMT_CMN=$(realpath "${TOPDIR}/../sonic-mgmt-common")
MLIST="${YANG_MODELS_PATH}/models_list"
if ! grep -qx "openconfig-interfaces.yang" "${MLIST}" 2>/dev/null; then
    echo "==== Regenerating ${MLIST} to load OpenConfig models (was dangling/incomplete)"
    rm -f "${MLIST}"
    cat "${MGMT_CMN}/config/transformer/models_list" > "${MLIST}"
    # Exclude sonic dependency yangs (SONIC_DEP_YANGS = build/yang/sonic/common/*.yang),
    # matching the mgmt-common build rule for build/transformer/models_list.
    for f in "${MGMT_CMN}"/build/yang/sonic/common/*.yang; do
        [ -e "$f" ] && printf -- "-%s\n" "$(basename "$f")" >> "${MLIST}"
    done
fi

# 2c. Ensure the CVL schema is present so SET operations actually persist.
#
# translib's write path (common_app.cmnAppCRUCommonDbOpn) orders the tables to
# write via cvl.SortDepTables(), which needs the compiled CVL schema (.yin files
# under ${CVL_SCHEMA_PATH}). That directory is only populated by a full
# mgmt-common build; off-box it is empty, so SortDepTables() returns an EMPTY
# table list (with no error) and every write is silently skipped -- the gNMI Set
# returns OK (returnCode 0) but nothing is committed to the virtual DB, breaking
# set->get round trips. Generate the schema here (same rule as cvl/Makefile's
# "schema" target: generate_yin.py over build/yang/sonic + models/yang/common).
if [ -z "$(ls -A "${CVL_SCHEMA_PATH}" 2>/dev/null)" ]; then
    echo "==== Generating CVL schema into ${CVL_SCHEMA_PATH} (was empty; SET would not persist)"
    mkdir -p "${CVL_SCHEMA_PATH}"
    python3 "${MGMT_CMN}/cvl/tools/generate_yin.py" \
        --path="${MGMT_CMN}/build/yang/sonic" \
        --path="${MGMT_CMN}/models/yang/common" \
        --out-dir="${CVL_SCHEMA_PATH}"
fi

# 3. Run the jsontest harness. Working directory is the gnmi_server package so
#    the harness can find ../testdata/json_tests.
export CGO_LDFLAGS="${CGO_LDFLAGS:--lswsscommon -lhiredis}"
export CGO_CXXFLAGS="${CGO_CXXFLAGS:--I/usr/include/swss -w -Wall -fpermissive}"
export JSON_TGT

echo "==== Running jsontest (JSON_TGT=${JSON_TGT})"
${GO:-go} test -mod=vendor -gcflags=all=-l -v \
    -run 'TestGnmiJson' \
    github.com/sonic-net/sonic-gnmi/gnmi_server
