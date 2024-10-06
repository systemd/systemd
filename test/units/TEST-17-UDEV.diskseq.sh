#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2010
# shellcheck disable=SC2317
set -ex
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# This is a test case for issue #34637.

at_exit() (
    set +e

    systemctl stop test-diskseq.service || :
    rm -f /run/systemd/system/test-diskseq.service
    systemctl daemon-reload

    [[ -d "$TMPDIR" ]] && rm -rf "$TMPDIR"

    udevadm control --log-level=info
)

trap at_exit EXIT

udevadm control --log-level=debug

TMPDIR="$(mktemp -d)"
truncate -s 16M "$TMPDIR"/foo.raw
mkfs.ext4 -L foo "$TMPDIR"/foo.raw

mkdir -p /run/systemd/system/
cat >/run/systemd/system/test-diskseq.service <<EOF
[Unit]
StartLimitIntervalSec=0
[Service]
ExecStart=false
Restart=on-failure
MountImages=$TMPDIR/foo.raw:/var
EOF
systemctl daemon-reload

udevadm settle

# If an initrd from the host is used, stack directories for by-diskseq symlinks
# may already exist. Save the number of the directories here.
NUM_DISKSEQ_EXPECTED=$(ls /run/udev/links | grep -c by-diskseq || :)

systemctl start --no-block test-diskseq.service

for _ in {0..100}; do
    sleep .1
    assert_eq "$(ls /run/udev/links | grep -c by-diskseq || :)" "$NUM_DISKSEQ_EXPECTED"
done

exit 0
