#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# Tests for issue #28588 and #28653.

assert_in "systemd-tmpfiles-setup-dev.service" "$(systemctl show --property After --value systemd-udevd.service)"
assert_in "systemd-udevd.service" "$(systemctl show --property Before --value systemd-tmpfiles-setup-dev.service)"

if [[ -f /dev/vfio/vfio ]]; then
   assert_in "crw-rw-rw-" "$(stat --format=%A /dev/vfio/vfio)"
fi

exit 0
