#!/usr/bin/env bash
#
# jsontest-offbox.sh: Driver to run the gNMI jsontest framework OFF-BOX (no
# switch) inside a sonic-slave-trixie container, against a local redis instance
# that stands in for the SONiC databases (a "virtual DB").
#
# The first run PROVISIONS a persistent container: it installs the SONiC-built
# libraries the CGO gnmi build links against (libswsscommon, the sonic libnl-3
# set, libyang), plus redis, then patches/builds the Go vendor tree
# (make sonic-gnmi). Subsequent runs REUSE that container and jump straight to
# the test -- so re-running a case takes seconds instead of minutes.
#
#   - container missing      -> create it, install deps, build, run test
#   - container present/stopped -> start it (if needed) and just run the test
#   - FORCE_REBUILD=1        -> delete + reprovision from scratch
#
# Run this from anywhere; paths are resolved relative to the script. Requires a
# prior full build (so target/debs/trixie/*.deb and build/yang exist).
#
# Usage:
#   src/sonic-gnmi/tools/jsontest-offbox.sh [JSON_TGT]
# Examples:
#   src/sonic-gnmi/tools/jsontest-offbox.sh                              # all cases
#   src/sonic-gnmi/tools/jsontest-offbox.sh oc_intf_mtu_roundtrip.json   # one case
#   FORCE_REBUILD=1 src/sonic-gnmi/tools/jsontest-offbox.sh              # fresh container
#
# Overridable via env: CONTAINER, IMAGE, HTTP_PROXY_VAL, FORCE_REBUILD.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
BLDROOT=$(cd "${SCRIPT_DIR}/../../.." && pwd)   # .../sonic-buildimage
JSON_TGT="${1:-oc_intf_mtu_roundtrip.json}"
CONTAINER="${CONTAINER:-jsontest-runner}"
IMAGE="${IMAGE:-$(docker images --format '{{.Repository}}:{{.Tag}}' | grep -m1 '^sonic-slave-trixie:')}"
# apt + go module download need egress; reuse the host proxy if set.
HTTP_PROXY_VAL="${HTTP_PROXY_VAL:-${http_proxy:-}}"

[ -n "${IMAGE}" ] || { echo "ERROR: no sonic-slave-trixie image found (build first)"; exit 1; }
[ -d "${BLDROOT}/target/debs/trixie" ] || { echo "ERROR: ${BLDROOT}/target/debs/trixie missing (build first)"; exit 1; }

echo "==== image=${IMAGE} container=${CONTAINER} repo=${BLDROOT}"
echo "==== JSON_TGT=${JSON_TGT}"

# FORCE_REBUILD=1 discards any existing container so it is reprovisioned.
if [ "${FORCE_REBUILD:-0}" = "1" ]; then
    docker rm -f "${CONTAINER}" >/dev/null 2>&1 || true
fi

# Does the container already exist? (any state: running or exited)
if docker inspect "${CONTAINER}" >/dev/null 2>&1; then
    CONTAINER_EXISTS=1
else
    CONTAINER_EXISTS=0
fi

if [ "${CONTAINER_EXISTS}" = "1" ]; then
    # Reuse: start it if it is stopped, then skip deps + build.
    if [ "$(docker inspect -f '{{.State.Running}}' "${CONTAINER}")" != "true" ]; then
        echo "==== reusing container ${CONTAINER} (was stopped; starting)"
        docker start "${CONTAINER}" >/dev/null
    else
        echo "==== reusing running container ${CONTAINER}"
    fi
    echo "==== skipping deps/build (already provisioned; use FORCE_REBUILD=1 to redo)"
else

# 1. Fresh container with the repo mounted at /sonic.
docker run -d --name "${CONTAINER}" \
    -e http_proxy="${HTTP_PROXY_VAL}" -e https_proxy="${HTTP_PROXY_VAL}" \
    -e no_proxy=localhost,127.0.0.1 \
    -v "${BLDROOT}:/sonic" \
    "${IMAGE}" sleep infinity >/dev/null
echo "==== container started"

# 2. Install SONiC-built CGO deps + redis. The sonic libnl-3 debs are required
#    because libswsscommon references versioned libnl symbols that the stock
#    Debian libnl3 does not provide.
docker exec "${CONTAINER}" bash -lc '
    set -e
    export DEBIAN_FRONTEND=noninteractive
    D=/sonic/target/debs/trixie
    echo "---- installing sonic libnl3 (200 + dev, replacing stock) / libyang3 / libswsscommon"
    # Install the whole sonic libnl-3 set -- both runtime (-200) and -dev -- so
    # their versions stay consistent. The stock Debian libnl-3-dev pins the exact
    # stock -200 version, so installing only the sonic -200 leaves apt in a broken
    # state; --force-all lets the sonic build (which carries the versioned symbols
    # libswsscommon needs) replace the stock packages cleanly.
    dpkg -i --force-all \
        $D/libnl-3-200_*.deb     $D/libnl-3-dev_*.deb \
        $D/libnl-genl-3-200_*.deb  $D/libnl-genl-3-dev_*.deb \
        $D/libnl-route-3-200_*.deb $D/libnl-route-3-dev_*.deb \
        $D/libnl-cli-3-200_*.deb   $D/libnl-cli-3-dev_*.deb \
        $D/libnl-nf-3-200_*.deb    $D/libnl-nf-3-dev_*.deb \
        $D/libyang3_*.deb          $D/libyang-dev_*.deb \
        $D/libswsscommon_*.deb     $D/libswsscommon-dev_*.deb
    ldconfig
    if ! command -v redis-server >/dev/null 2>&1; then
        echo "---- installing redis"
        apt-get update -y
        apt-get install -y redis-server redis-tools || apt-get -f install -y
    fi
'
echo "==== deps installed"

# 3. Generate + patch the Go vendor tree. "make sonic-gnmi" runs go-deps (go mod
#    vendor + sonic-mgmt-common/gnmi_path patches) AND the extra vendor patches
#    that only the build target applies -- notably the advancedtls fix
#    (0002-Fix-advance-tls-build-with-go-119.patch); without it the gnmi_server
#    test binary fails to compile (undefined: advancedtls.CheckChainRevocation).
docker exec "${CONTAINER}" bash -lc '
    set -e
    export GOPATH=/tmp/go GOSUMDB=off
    export CGO_LDFLAGS="-lswsscommon -lhiredis"
    export CGO_CXXFLAGS="-I/usr/include/swss -w -Wall -fpermissive"
    git config --global --add safe.directory "*"
    cd /sonic/src/sonic-gnmi
    echo "---- make sonic-gnmi (vendor + all patches + build)"
    make sonic-gnmi
'
echo "==== vendor ready"

fi  # end provisioning (create + deps + build) for a brand-new container

# 4. Run the jsontest harness (starts redis, self-heals models_list + CVL schema).
docker exec "${CONTAINER}" bash -lc "
    export GOPATH=/tmp/go GOSUMDB=off
    cd /sonic/src/sonic-gnmi
    JSON_TGT='${JSON_TGT}' bash tools/test/run-jsontest.sh
"
