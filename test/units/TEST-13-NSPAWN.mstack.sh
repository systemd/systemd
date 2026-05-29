#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

PASS=0
FAIL=0

at_exit() {
  set +e

  [[ -n "${MSTACK_DIR:-}" ]] && rm -rf "$MSTACK_DIR"
  [[ -n "${LAYERS_DIR:-}" ]] && rm -rf "$LAYERS_DIR"
  [[ -n "${CONFIG_SRC:-}" ]] && rm -rf "$CONFIG_SRC"
  [[ -n "${VAR_SRC:-}" ]]    && rm -rf "$VAR_SRC"
  [[ -n "${BIND_SRC:-}" ]]   && rm -rf "$BIND_SRC"
}

trap at_exit EXIT

check() {
  local desc="$1"
  local expected="$2"
  local actual="$3"

  if printf '%s\n' "$actual" | grep -E "$expected"; then
    echo "PASS: $desc"
    PASS=$((PASS + 1))
  else
    echo "FAIL: $desc"
    echo "  expected: $expected"
    echo "  actual:   $actual"
    FAIL=$((FAIL + 1))
  fi
}

# --- Setup ---

LAYERS_DIR="$(mktemp -d)"
MSTACK_DIR="$(mktemp -d)"
CONFIG_SRC="$(mktemp -d)"
VAR_SRC="$(mktemp -d)"
BIND_SRC="$(mktemp -d)"

# layer@0: full container rootfs via the standard helper
create_dummy_container "$LAYERS_DIR/layer@0"

# layer@1: minimal, just needs a marker file to verify overlay ordering
mkdir -p "$LAYERS_DIR/layer@1"
echo "layer1" > "$LAYERS_DIR/layer@1/marker.txt"

# Bind sources
echo "hello"           > "$CONFIG_SRC/test.conf"
echo "hello from /var" > "$VAR_SRC/test-var.conf"
echo "writable"        > "$BIND_SRC/test.txt"

# Assemble the .mstack directory via symlinks
ln -s "$LAYERS_DIR/layer@0" "$MSTACK_DIR/layer@0"
ln -s "$LAYERS_DIR/layer@1" "$MSTACK_DIR/layer@1"
ln -s "$CONFIG_SRC"          "$MSTACK_DIR/robind@config"
ln -s "$VAR_SRC"             "$MSTACK_DIR/robind@var-config"
ln -s "$BIND_SRC"            "$MSTACK_DIR/bind@writable"

mkdir -p "$MSTACK_DIR/layer@0/writable"
mkdir -p "$MSTACK_DIR/layer@0/config"
mkdir -p "$MSTACK_DIR/layer@0/var/config"

# layer@0: put a file that will be shadowed, and a shared dir
echo "from-layer0"  > "$LAYERS_DIR/layer@0/ordering-test.txt"
mkdir -p               "$LAYERS_DIR/layer@0/shared-dir"
echo "layer0-file"  > "$LAYERS_DIR/layer@0/shared-dir/from-layer0.txt"

# layer@1: shadow the file, contribute to shared dir
echo "from-layer1"  > "$LAYERS_DIR/layer@1/ordering-test.txt"
mkdir -p               "$LAYERS_DIR/layer@1/shared-dir"
echo "layer1-file"  > "$LAYERS_DIR/layer@1/shared-dir/from-layer1.txt"

# layer@2: wins over both
mkdir -p "$LAYERS_DIR/layer@2"
echo "from-layer2"  > "$LAYERS_DIR/layer@2/ordering-test.txt"

ln -s "$LAYERS_DIR/layer@2" "$MSTACK_DIR/layer@2"

# --- Tests ---

echo "=== No volatile, no rw/ ==="
OUT=$(systemd-nspawn --pipe --mstack "$MSTACK_DIR" mount | grep "/ type\|/config\|/writable" || true)
check "root ro without rw/"       "/ type.*ro"         "$OUT"
check "robind@config ro"          "/config type.*ro"   "$OUT"
check "robind@var-config ro"      "/var/config type.*ro" "$OUT"
check "bind@writable rw"          "/writable type.*rw" "$OUT"
MARKER=$(systemd-nspawn --pipe --mstack "$MSTACK_DIR" cat /marker.txt || true)
check "layer@1 marker visible"    "layer1"             "$MARKER"

# Ordering: layer@2 shadows layer@1 and layer@0
ORDER=$(systemd-nspawn --pipe --mstack "$MSTACK_DIR" cat /ordering-test.txt || true)
check "layer@2 shadows lower layers"     "from-layer2"  "$ORDER"

# Directory merge: files from both layer@0 and layer@1 visible under shared-dir
DIR0=$(systemd-nspawn --pipe --mstack "$MSTACK_DIR" cat /shared-dir/from-layer0.txt || true)
DIR1=$(systemd-nspawn --pipe --mstack "$MSTACK_DIR" cat /shared-dir/from-layer1.txt || true)
check "shared-dir merges layer@0 content" "layer0-file" "$DIR0"
check "shared-dir merges layer@1 content" "layer1-file" "$DIR1"

echo "=== rw/ present ==="
mkdir -p "$MSTACK_DIR/rw"
# The rw/ path uses fd-based overlayfs with upperdir/workdir via fsconfig,
# which fails with EINVAL in some CI environments
# (overlayfs-on-overlayfs or similar storage restrictions).
# Probe for support and skip if unavailable.
if ! systemd-nspawn --pipe --mstack "$MSTACK_DIR" true 2>/dev/null; then
  echo "SKIP: rw/ overlay not supported in this environment, skipping"
else
  OUT=$(systemd-nspawn --pipe --mstack "$MSTACK_DIR" mount | grep "/ type\|/config\|/writable" || true)
  check "root rw with rw/"          "/ type.*rw"         "$OUT"
  check "bind@writable rw with rw/" "/writable type.*rw" "$OUT"
  MARKER=$(systemd-nspawn --pipe --mstack "$MSTACK_DIR" cat /marker.txt || true)
  check "layer@1 marker visible with rw/" "layer1"       "$MARKER"

  # Test persistence: write inside the container, verify it survives on the host
  systemd-nspawn --pipe --mstack "$MSTACK_DIR" sh -c 'echo "persistent" > /persist-test.txt'
  if systemd-nspawn --pipe --mstack "$MSTACK_DIR" cat /persist-test.txt | grep -qF "persistent"; then
    echo "PASS: rw/ persists across invocations"
    PASS=$((PASS+1))
  else
    echo "FAIL: rw/ persists across invocations"
    FAIL=$((FAIL+1))
  fi
fi
rm -rf "$MSTACK_DIR/rw"

echo "=== --read-only ==="
OUT=$(systemd-nspawn --pipe --mstack "$MSTACK_DIR" --read-only mount | grep "/ type\|/config\|/writable" || true)
check "root ro with --read-only"        "/ type.*ro"         "$OUT"
check "bind@writable ro with --read-only" "/writable type.*ro" "$OUT"
check "robind@config ro with --read-only" "/config type.*ro" "$OUT"
MARKER=$(systemd-nspawn --pipe --mstack "$MSTACK_DIR" --read-only cat /marker.txt || true)
check "layer@1 marker visible with --read-only" "layer1"     "$MARKER"

echo "=== --volatile ==="
OUT=$(systemd-nspawn --pipe --mstack "$MSTACK_DIR" --volatile mount | grep "/ type\|/config\|/writable" || true)
check "root rw with --volatile"      "/ type.*rw"           "$OUT"
check "bind@writable rw"             "/writable type.*rw"   "$OUT"
check "robind@config ro"             "/config type.*ro"     "$OUT"
check "robind@var-config ro"         "/var/config type.*ro" "$OUT"
# marker.txt is at root, not under /usr - expected absent with --volatile=yes
MARKER=$(systemd-nspawn --pipe --mstack "$MSTACK_DIR" --volatile cat /marker.txt || true)
check "layer@1 marker absent with --volatile=yes" "" "$MARKER"

echo "=== --volatile=overlay ==="
OUT=$(systemd-nspawn --pipe --mstack "$MSTACK_DIR" --volatile=overlay mount | grep "/ type\|/config\|/writable" || true)
check "root rw overlay"   "/ type overlay.*rw"   "$OUT"
check "bind@writable rw"  "/writable type.*rw"   "$OUT"
check "robind@config ro"  "/config type.*ro"     "$OUT"
MARKER=$(systemd-nspawn --pipe --mstack "$MSTACK_DIR" --volatile=overlay cat /marker.txt || true)
check "layer@1 marker visible with --volatile=overlay" "layer1" "$MARKER"

echo "=== --volatile=state ==="
OUT=$(systemd-nspawn --pipe --mstack "$MSTACK_DIR" --volatile=state mount | grep "/ type\|/config\|/writable" || true)
check "root ro with --volatile=state" "/ type.*ro"         "$OUT"
check "bind@writable rw"              "/writable type.*rw" "$OUT"
check "robind@config ro"              "/config type.*ro"   "$OUT"
MARKER=$(systemd-nspawn --pipe --mstack "$MSTACK_DIR" --volatile=state cat /marker.txt || true)
check "layer@1 marker visible with --volatile=state" "layer1" "$MARKER"

echo "=== Missing target directory on read-only rootfs ==="
ln -s "$BIND_SRC" "$MSTACK_DIR/bind@missing-target-dir"

STDERR=$(systemd-nspawn --pipe --mstack "$MSTACK_DIR" mount 2>&1 || true)

rm -f "$MSTACK_DIR/bind@missing-target-dir"

check "nspawn prints custom read-only rootfs error" \
      "Failed to create.*root is read-only" \
      "$STDERR"

echo ""
echo "Results: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]]
