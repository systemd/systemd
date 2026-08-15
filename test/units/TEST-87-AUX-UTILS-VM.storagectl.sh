#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

if ! command -v storagectl >/dev/null; then
    echo "storagectl not found, skipping."
    exit 77
fi

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# Unset $PAGER so we don't have to use --no-pager everywhere
export PAGER=

# storagectl runs in a VM-only test
if systemd-detect-virt -cq ; then
    echo "can't run in a container, skipping."
    exit 77
fi

at_exit() {
    set +e

    if [[ -n "${MOUNT_DIR:-}" ]] && mountpoint -q "$MOUNT_DIR"; then
        umount "$MOUNT_DIR"
    fi
    if [[ -n "${LOOP:-}" ]]; then
        systemd-dissect --detach "$LOOP"
    fi
    if [[ -n "${WORK_DIR:-}" ]]; then
        rm -fr "$WORK_DIR"
    fi
    rm -fr /var/lib/storage/test-87-storage-*.volume
}
trap at_exit EXIT

# The storage providers are socket-activated by sockets.target, so the listening
# AF_UNIX sockets should already exist.
test -S /run/systemd/io.systemd.StorageProvider/block
test -S /run/systemd/io.systemd.StorageProvider/fs

WORK_DIR="$(mktemp -d /tmp/test-storagectl.XXXXXXXXXX)"
MOUNT_DIR="$WORK_DIR/mnt"
mkdir -p "$MOUNT_DIR"

# --- storagectl basic ---

storagectl --help
storagectl --version
storagectl help

# Unknown verb / option
(! storagectl this-verb-does-not-exist)
(! storagectl --no-such-option providers)

# --- storagectl providers ---

storagectl providers
storagectl providers --no-legend
storagectl providers --no-pager
storagectl providers --json=pretty | jq .
storagectl providers --json=short | jq .

providers_output="$(storagectl providers --no-legend)"
assert_in 'block' "$providers_output"
assert_in 'fs'    "$providers_output"
assert_in 'yes'   "$providers_output"

# --- storagectl volumes ---

# 'volumes' is the default verb
storagectl
storagectl volumes
storagectl volumes --no-legend
storagectl volumes --no-pager
storagectl volumes --json=pretty | jq .
storagectl volumes --json=short  | jq .

# Glob filter that matches nothing should not error
storagectl volumes 'no-such-volume-*'

# --- storagectl templates ---

storagectl templates
storagectl templates --no-legend --no-pager
storagectl templates --json=pretty | jq .
storagectl templates --json=short  | jq --seq .

templates_output="$(storagectl templates --no-legend)"
assert_in 'sparse-file'    "$templates_output"
assert_in 'allocated-file' "$templates_output"
assert_in 'directory'      "$templates_output"
assert_in 'subvolume'      "$templates_output"

# Glob filter
storagectl templates 'sparse-*' --no-legend | grep sparse-file >/dev/null
(! storagectl templates 'sparse-*' --no-legend | grep allocated-file >/dev/null)
storagectl templates 'no-such-template-*'

# --- direct varlink calls ---

varlinkctl introspect /run/systemd/io.systemd.StorageProvider/block io.systemd.StorageProvider
varlinkctl introspect /run/systemd/io.systemd.StorageProvider/fs    io.systemd.StorageProvider

# Block provider does not expose templates
varlinkctl call --more /run/systemd/io.systemd.StorageProvider/block \
    io.systemd.StorageProvider.ListTemplates '{}' \
    --graceful=io.systemd.StorageProvider.NoSuchTemplate

# fs provider lists the four built-in templates
varlinkctl call --more --json=short /run/systemd/io.systemd.StorageProvider/fs \
    io.systemd.StorageProvider.ListTemplates '{}' | grep '"name":"sparse-file"' >/dev/null

# Block provider rejects names not under /dev/
varlinkctl call /run/systemd/io.systemd.StorageProvider/block \
    io.systemd.StorageProvider.Acquire '{"name":"/tmp/no-such-dev"}' \
    --graceful=io.systemd.StorageProvider.NoSuchVolume

# fs provider rejects bad volume names (contain '/' → not a valid filename)
varlinkctl call /run/systemd/io.systemd.StorageProvider/fs \
    io.systemd.StorageProvider.Acquire '{"name":"bad/name"}' \
    --graceful=org.varlink.service.InvalidParameter

# --- mount.storage: regular file via fs provider ---

TESTVOL_REG="test-87-storage-reg-$RANDOM"
truncate -s 32M "/var/lib/storage/$TESTVOL_REG.volume"
mkfs.ext4 "/var/lib/storage/$TESTVOL_REG.volume"
mount -t storage.ext4 "fs:$TESTVOL_REG" "$MOUNT_DIR"
mountpoint -q "$MOUNT_DIR"
echo "hello reg" >"$MOUNT_DIR/hello"
umount "$MOUNT_DIR"

# Volume now appears in 'storagectl volumes'
volumes_after_create="$(storagectl volumes "$TESTVOL_REG" --no-legend)"
assert_in "$TESTVOL_REG" "$volumes_after_create"
assert_in 'reg'          "$volumes_after_create"

# Re-mount existing (default storage.create=any)
mount -t storage.ext4 "fs:$TESTVOL_REG" "$MOUNT_DIR"
test -f "$MOUNT_DIR/hello"
umount "$MOUNT_DIR"

# storage.create=open succeeds for existing volume
mount -t storage.ext4 -o "storage.create=open" "fs:$TESTVOL_REG" "$MOUNT_DIR"
umount "$MOUNT_DIR"

# storage.create=new on existing volume must fail
(! mount -t storage.ext4 -o "storage.create=new,storage.create-size=16M" "fs:$TESTVOL_REG" "$MOUNT_DIR")

# Read-only mount
mount -t storage.ext4 -o ro "fs:$TESTVOL_REG" "$MOUNT_DIR"
findmnt -n -o options "$MOUNT_DIR" | grep -E '(^|,)ro(,|$)' >/dev/null
(! touch "$MOUNT_DIR/readonly-test")
umount "$MOUNT_DIR"

rm -f "/var/lib/storage/$TESTVOL_REG.volume"

# storage.create=open on missing volume must fail
(! mount -t storage.ext4 -o "storage.create=open" "fs:test-87-storage-missing-$RANDOM" "$MOUNT_DIR")

# --- mount.storage: directory volume via fs provider (requires idmapped mounts) ---

TESTVOL_DIR="test-87-storage-dir-$RANDOM"
if mount -t storage "fs:$TESTVOL_DIR" "$MOUNT_DIR"; then
    mountpoint -q "$MOUNT_DIR"
    test -d "/var/lib/storage/$TESTVOL_DIR.volume/root"
    echo "dir test" >"$MOUNT_DIR/hello"
    test -f "/var/lib/storage/$TESTVOL_DIR.volume/root/hello"
    umount "$MOUNT_DIR"
    rm -fr "/var/lib/storage/$TESTVOL_DIR.volume"
else
    echo "Directory volume mounting failed (idmapped mounts unsupported?), skipping."
    rm -fr "/var/lib/storage/$TESTVOL_DIR.volume"
fi

# --- mount.storage: block device via block provider ---

truncate -s 32M "$WORK_DIR/block.img"
mkfs.ext4 -L sd-storage-blk "$WORK_DIR/block.img"
LOOP="$(systemd-dissect --attach --loop-ref=test-storagectl "$WORK_DIR/block.img")"

mount -t storage.ext4 "block:$LOOP" "$MOUNT_DIR"
mountpoint -q "$MOUNT_DIR"
echo "hello blk" >"$MOUNT_DIR/hello"
umount "$MOUNT_DIR"

# Read-only mount of the block volume
mount -t storage.ext4 -o ro "block:$LOOP" "$MOUNT_DIR"
findmnt -n -o options "$MOUNT_DIR" | grep -E '(^|,)ro(,|$)' >/dev/null
test -f "$MOUNT_DIR/hello"
umount "$MOUNT_DIR"

# Block volume is enumerable; matchName globs over device node and aliases
varlinkctl call --more --json=short /run/systemd/io.systemd.StorageProvider/block \
    io.systemd.StorageProvider.ListVolumes "{\"matchName\":\"$LOOP\"}" |
    grep '"type":"blk"' >/dev/null

systemd-dissect --detach "$LOOP"
unset LOOP

# --- error cases ---

# Bad provider name (no such socket)
(! mount -t storage.ext4 "no-such-provider:foo" "$MOUNT_DIR")
# Bad volume specification (no colon)
(! mount -t storage.ext4 "no-colon-here" "$MOUNT_DIR")
# Refuse nested storage volumes (FS type "storage.storage")
(! mount -t storage.storage "fs:something" "$MOUNT_DIR")
