#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh
# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

mkdir -p /usr/share/empty.sshd
test/units/testsuite-74.networkctl.sh
# Writable /usr overlay required to possibly make /usr/share/empty.sshd
# and write networkd config to /usr to test runtime masking.
maybe_mount_usr_overlay
trap 'maybe_umount_usr_overlay' EXIT

run_subtests

touch /testok
