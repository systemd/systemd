#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

CAT_PID="$(systemd-notify --fork -- systemd-socket-activate -l 1234 --accept --inetd cat)"
assert_eq "$(echo -n hello | socat - 'TCP:localhost:1234')" hello
kill "$CAT_PID"

# Check whether socat's ACCEPT-FD is available (introduced in v1.8)
systemd-socket-activate -l 1234 --now socat ACCEPT-FD:3 PIPE &
sleep 1
jobs >/dev/null
if kill %% &>/dev/null; then
    systemd-socket-activate -l 1234 --now socat ACCEPT-FD:3 PIPE &
    SOCAT_PID="$!"

    # unfortunately we need to sleep since socket-activate only sends sd_notify when --accept is passed,
    # so we can't rely on that to avoid a race.
    sleep 1

    assert_in socat "$(</proc/"$SOCAT_PID"/comm)"
    assert_eq "$(echo -n bye | socat - 'TCP:localhost:1234')" bye
fi

# --accept is not allowed with --now
(! systemd-socket-activate -l 1234 --accept --now cat)

# Multiple fds are not allowed with --inetd
(! systemd-socket-activate -l 1234 -l 4321 --inetd cat)
