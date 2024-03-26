#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh
# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# Needed to write /usr/lib/tmpfiles.d to test /etc overrides in testsuite-22.13.sh
maybe_mount_usr_overlay
trap 'maybe_umount_usr_overlay' EXIT

run_subtests

touch /testok
