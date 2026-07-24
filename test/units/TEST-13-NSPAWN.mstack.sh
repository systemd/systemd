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
  [[ -n "${ROOT_SRC:-}" ]]   && rm -rf "$ROOT_SRC"
  [[ -n "${TMPFS_RO_DIR:-}" ]] && rm -rf "$TMPFS_RO_DIR"
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

echo "=== root/ + layer@ + rw/ ==="
# root/ folds into the same overlay as layer@/rw as its base layer, rather than being mounted
# separately with only a /usr-only overlay submount on top of it - the whole tree (not just /usr/)
# goes through rw/'s copy-on-write mechanism, and root/'s own content merges with layer@ content
# across the whole tree.
ROOT_SRC="$(mktemp -d)"
mkdir -p "$ROOT_SRC/etc"
echo "root-etc-marker" > "$ROOT_SRC/etc/root-marker.txt"
ln -s "$ROOT_SRC" "$MSTACK_DIR/root"
mkdir -p "$MSTACK_DIR/rw"

if ! systemd-nspawn --pipe --mstack "$MSTACK_DIR" true 2>/dev/null; then
  echo "SKIP: root/+layer@+rw/ overlay not supported in this environment, skipping"
else
  ROOT_MARKER=$(systemd-nspawn --pipe --mstack "$MSTACK_DIR" cat /etc/root-marker.txt || true)
  check "root/'s own content visible" "root-etc-marker" "$ROOT_MARKER"

  LAYER_MARKER=$(systemd-nspawn --pipe --mstack "$MSTACK_DIR" cat /marker.txt || true)
  check "layer@1 content visible alongside root/" "layer1" "$LAYER_MARKER"

  # Write outside /usr/ (unrelated to any layer@ content) must land in rw/, not fail, and not
  # mutate root/'s own source directory on the host.
  systemd-nspawn --pipe --mstack "$MSTACK_DIR" sh -c 'echo written > /etc/new-file.txt'
  NEW_FILE=$(systemd-nspawn --pipe --mstack "$MSTACK_DIR" cat /etc/new-file.txt || true)
  check "write outside /usr/ persists via rw/" "written" "$NEW_FILE"

  if [[ -e "$ROOT_SRC/etc/new-file.txt" ]]; then
    echo "FAIL: write outside /usr/ leaked into root/'s own source directory on the host"
    FAIL=$((FAIL+1))
  else
    echo "PASS: root/'s own source directory on the host stayed untouched"
    PASS=$((PASS+1))
  fi
fi
# rw/ must be gone before the next section: .mstack/ rw/ and --volatile= are mutually exclusive
# (nspawn refuses the combination outright), so a leftover rw/ here would make every check below
# fail on that refusal instead of what they're actually testing.
rm -rf "$MSTACK_DIR/rw"

echo "=== root/ + --volatile=yes ==="
# Regression test: /usr/ is extracted from the fully assembled tree (root/ folded in, per above)
# after mstack_make_mounts() runs; the throwaway root this produces must stay writable (a stale
# mstack->root_mount pointer once made mstack_bind_mounts() think it still had to protect a real
# root/ entry, incorrectly leaving the fresh tmpfs read-only and breaking container startup).
OUT=$(systemd-nspawn --pipe --mstack "$MSTACK_DIR" --volatile mount | grep "/ type\|/usr type" || true)
check "root writable with root/ + --volatile=yes" "/ type.*rw" "$OUT"
check "/usr/ read-only with root/ + --volatile=yes" "/usr type.*ro" "$OUT"

ROOT_MARKER_YES=$(systemd-nspawn --pipe --mstack "$MSTACK_DIR" --volatile cat /etc/root-marker.txt 2>&1 || true)
check "root/'s own content (outside /usr/) absent with --volatile=yes" "No such file or directory" "$ROOT_MARKER_YES"

rm -rf "$MSTACK_DIR/root" "$ROOT_SRC"

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
MARKER=$(systemd-nspawn --pipe --mstack "$MSTACK_DIR" --volatile cat /marker.txt 2>&1 || true)
check "layer@1 marker absent with --volatile=yes" "No such file or directory" "$MARKER"

echo "=== --volatile=overlay ==="
OUT=$(systemd-nspawn --pipe --mstack "$MSTACK_DIR" --volatile=overlay mount | grep "/ type\|/config\|/writable" || true)
check "root rw overlay"   "/ type overlay.*rw"   "$OUT"
check "bind@writable rw"  "/writable type.*rw"   "$OUT"
check "robind@config ro"  "/config type.*ro"     "$OUT"
MARKER=$(systemd-nspawn --pipe --mstack "$MSTACK_DIR" --volatile=overlay cat /marker.txt || true)
check "layer@1 marker visible with --volatile=overlay" "layer1" "$MARKER"

echo "=== --volatile=state ==="
OUT=$(systemd-nspawn --pipe --mstack "$MSTACK_DIR" --volatile=state mount | grep "/ type\|/config\|/writable\|/var type" || true)
check "root ro with --volatile=state" "/ type.*ro"         "$OUT"
check "/var is a fresh tmpfs"         "/var type.*rw"       "$OUT"
check "bind@writable rw"              "/writable type.*rw" "$OUT"
check "robind@config ro"              "/config type.*ro"   "$OUT"
MARKER=$(systemd-nspawn --pipe --mstack "$MSTACK_DIR" --volatile=state cat /marker.txt || true)
check "layer@1 marker visible with --volatile=state" "layer1" "$MARKER"

# --volatile=state's /var is a synthetic tmpfs@ entry realized fresh on every invocation (see
# mstack_merge_volatile() in mstack.c) - writes to it must never survive across invocations.
systemd-nspawn --pipe --mstack "$MSTACK_DIR" --volatile=state sh -c 'echo "should-not-persist" > /var/state-write-test.txt'
STATE_WRITE=$(systemd-nspawn --pipe --mstack "$MSTACK_DIR" --volatile=state cat /var/state-write-test.txt 2>&1 || true)
check "writes to --volatile=state's /var are discarded" "No such file or directory" "$STATE_WRITE"

echo "=== tmpfs@ entry ==="
mkdir -p "$MSTACK_DIR/tmpfs@extra"

# tmpfs@ mount points, like bind@/robind@, are created on demand under MSTACK_DEFER_MOUNT: their
# parent directory is pre-created while root is still writable (see the pre-create loop in
# mstack_bind_mounts() in mstack.c). That only helps if root has an upperdir to actually create the
# new /extra mountpoint directory in, though - a bare layer@-only overlay with no rw/ (what
# $MSTACK_DIR is at this point: layer@0/1/2, no root/, no rw/) has no upperdir at all, so it can't
# create anything new any more than bind@ can (see "Missing target directory on read-only rootfs"
# below) - use an isolated root/-only .mstack/ instead (reusing layer@0's content, so "mount" is
# actually available inside), which - unlike an overlay - is a plain bind of a real (and thus
# genuinely writable) directory right up until mstack_apply_attr() marks it read-only afterwards,
# so the pre-create loop's mkdir has somewhere to actually land.
TMPFS_RO_DIR="$(mktemp -d)"
ln -s "$LAYERS_DIR/layer@0" "$TMPFS_RO_DIR/root"
mkdir -p "$TMPFS_RO_DIR/tmpfs@extra"

OUT=$(systemd-nspawn --pipe --mstack "$TMPFS_RO_DIR" mount | grep "/ type\|/extra type" || true)
check "root stays ro with tmpfs@ present" "/ type.*ro" "$OUT"
check "tmpfs@extra mounts a fresh tmpfs on a read-only root" "/extra type.*rw" "$OUT"

rm -rf "$TMPFS_RO_DIR"

OUT=$(systemd-nspawn --pipe --mstack "$MSTACK_DIR" --volatile=overlay mount | grep "/extra type" || true)
check "tmpfs@extra mounts a fresh tmpfs" "/extra type.*rw" "$OUT"
systemd-nspawn --pipe --mstack "$MSTACK_DIR" --volatile=overlay sh -c 'echo "should-not-persist" > /extra/tmpfs-write-test.txt'
TMPFS_WRITE=$(systemd-nspawn --pipe --mstack "$MSTACK_DIR" --volatile=overlay cat /extra/tmpfs-write-test.txt 2>&1 || true)
check "writes to tmpfs@ entries are discarded" "No such file or directory" "$TMPFS_WRITE"
rm -rf "$MSTACK_DIR/tmpfs@extra"

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
