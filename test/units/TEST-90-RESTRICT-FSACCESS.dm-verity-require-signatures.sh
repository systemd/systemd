#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# With dm_verity.require_signatures=1, the kernel refuses a Verity image without a signature.
# Check that systemd-dissect refuses such an image, and doesn't wait for a password that never
# comes. This only needs require_signatures=1, no BPF or .dm-verity keyring support.
set -eux
set -o pipefail

if [[ ! -e /sys/module/dm_verity/parameters/require_signatures ]]; then
    modprobe dm_verity 2>/dev/null || true
fi
val="$(cat /sys/module/dm_verity/parameters/require_signatures 2>/dev/null || echo)"
if [[ "$val" != "Y" && "$val" != "1" ]]; then
    echo "require_signatures not enabled, skipping"
    exit 77
fi

UNSIGNED="$(mktemp -d)"
mkdir "$UNSIGNED/definitions" "$UNSIGNED/tree"
echo unsigned >"$UNSIGNED/tree/file"
tee "$UNSIGNED/definitions/10-root.conf" <<EOF
[Partition]
Type=root
Format=erofs
CopyFiles=$UNSIGNED/tree:/
Verity=data
VerityMatchKey=root
Minimize=best
EOF
tee "$UNSIGNED/definitions/11-root-verity.conf" <<EOF
[Partition]
Type=root-verity
Verity=hash
VerityMatchKey=root
Minimize=best
EOF
systemd-repart --empty=create --size=auto --dry-run=no --definitions="$UNSIGNED/definitions" "$UNSIGNED/image.raw"
rc=0
timeout 60 systemd-dissect --mount --mkdir "$UNSIGNED/image.raw" "$UNSIGNED/mnt" </dev/null 2>"$UNSIGNED/stderr" || rc=$?
cat "$UNSIGNED/stderr"
if [[ "$rc" -eq 0 || "$rc" -eq 124 ]]; then
    echo "ERROR: systemd-dissect didn't refuse the unsigned verity image (exit status $rc)" >&2
    exit 1
fi
grep -F 'Image lacks recognized signature' "$UNSIGNED/stderr" >/dev/null
rm -rf "$UNSIGNED"
echo "Unsigned verity image refused: OK"
