#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# Tests for issue #28588 and #28653.

# On boot, services need to be started in the following order:
# 1. systemd-tmpfiles-setup-dev-early.service
# 2. systemd-sysusers.service
# 3. systemd-tmpfiles-setup-dev.service
# 4. systemd-udevd.service

output="$(systemctl show --property After --value systemd-udevd.service)"
assert_in "systemd-tmpfiles-setup-dev-early.service" "$output"
assert_in "systemd-sysusers.service" "$output"
assert_in "systemd-tmpfiles-setup-dev.service" "$output"

output="$(systemctl show --property After --value systemd-tmpfiles-setup-dev.service)"
assert_in "systemd-tmpfiles-setup-dev-early.service" "$output"
assert_in "systemd-sysusers.service" "$output"

output="$(systemctl show --property After --value systemd-sysusers.service)"
assert_in "systemd-tmpfiles-setup-dev-early.service" "$output"

check_owner_and_mode() {
    local dev=${1?}
    local user=${2?}
    local group=${3?}
    local mode=${4:-}

    if [[ -e "$dev" ]]; then
        assert_in "$user" "$(stat --format=%U "$dev")"
        assert_in "$group" "$(stat --format=%G "$dev")"
        if [[ -n "$mode" ]]; then
            assert_in "$mode" "$(stat --format=%#0a "$dev")"
        fi
    fi

    return 0
}

# Check owner and access mode specified in static-nodes-permissions.conf
check_owner_and_mode /dev/snd/seq      root audio 0660
check_owner_and_mode /dev/snd/timer    root audio 0660
check_owner_and_mode /dev/loop-control root disk  0660
check_owner_and_mode /dev/net/tun      root root  0666
check_owner_and_mode /dev/fuse         root root  0666
check_owner_and_mode /dev/vfio/vfio    root root  0666
check_owner_and_mode /dev/kvm          root kvm
check_owner_and_mode /dev/vhost-net    root kvm
check_owner_and_mode /dev/vhost-vsock  root kvm

exit 0
