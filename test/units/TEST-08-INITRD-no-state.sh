#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

if systemd-detect-virt -qc; then
    echo >&2 "This test can't run in a container"
    exit 1
fi

# When --no-state is used for switch-root, the new system manager starts fresh
# without --switched-root and --deserialize. Verify that no initrd state was
# carried over.

# InitRDTimestampMonotonic is normally serialized from the initrd PID 1 and
# deserialized by the real-root PID 1. With --no-state there is no
# deserialization, so the timestamp must be 0.
if [[ "$(systemctl show -P InitRDTimestampMonotonic)" -ne 0 ]]; then
    echo >&2 "InitRDTimestampMonotonic is set, but --no-state should have prevented state transfer"
    exit 1
fi

# The fallback path in PID 1 moves /run/systemd to /run/systemd.pre-switch-root
# before exec'ing the new systemd. Verify that happened.
test -d /run/systemd.pre-switch-root

# Verify that initrd-originating units were not deserialized into the real-root
# manager. initrd-switch-root-no-state.service was active in the initrd; after a
# stateless switch-root the new manager should know nothing about it.
state=$(systemctl show -P LoadState initrd-switch-root-no-state.service 2>/dev/null)
if [[ "$state" != "not-found" ]]; then
    echo >&2 "initrd-switch-root-no-state.service should not be known to the new manager (LoadState=$state)"
    exit 1
fi

touch /testok
