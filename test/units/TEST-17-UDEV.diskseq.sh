#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2010
# shellcheck disable=SC2012
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
)

trap at_exit EXIT

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

udevadm settle --timeout=30

# Check if no lock file exists, if the lock directory exists.
if [[ -d /run/udev/links.lock/ ]]; then
    [[ "$(ls /run/udev/links.lock/ | wc -l)" == 0 ]]
fi

# Save the current number of the directories.
NUM_DISKSEQ=$(ls /run/udev/links/ | grep -c by-diskseq || :)

systemctl start --no-block test-diskseq.service

for _ in {0..100}; do
    sleep .1
    n=$(ls /run/udev/links/ | grep -c by-diskseq || :)
    (( n <= NUM_DISKSEQ + 1 ))
done

systemctl stop test-diskseq.service || :

udevadm settle --timeout=30

# Check if the lock directory exists, but no lock file exists in it.
[[ -d /run/udev/links.lock/ ]]
[[ "$(ls /run/udev/links.lock/ | wc -l)" == 0 ]]

exit 0
