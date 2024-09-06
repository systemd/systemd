#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

export NUM_REBOOT=4

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

systemd-cat echo "Reboot count: $REBOOT_COUNT"
systemd-cat journalctl --list-boots

run_subtests

if [[ "$REBOOT_COUNT" -lt "$NUM_REBOOT" ]]; then
    SYSTEMCTL_SKIP_AUTO_SOFT_REBOOT=1
    export SYSTEMCTL_SKIP_AUTO_SOFT_REBOOT
    systemctl_final reboot
    # Now block until the reboot killing spree kills us.
    exec sleep infinity
elif [[ "$REBOOT_COUNT" -gt "$NUM_REBOOT" ]]; then
    assert_not_reached
fi

touch /testok
