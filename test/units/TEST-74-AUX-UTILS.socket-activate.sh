#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

PID="$(systemd-notify --fork -- systemd-socket-activate -l 1234 --accept --inetd cat)"
assert_in systemd-socket "$(cat /proc/"$PID"/comm)"
assert_eq "$(echo -n hello | socat - 'TCP:localhost:1234')" hello
assert_in systemd-socket "$(cat /proc/"$PID"/comm)"
kill "$PID"
tail --pid="$PID" -f /dev/null

PID=$(systemd-notify --fork -- systemd-socket-activate -l 1234 --now socat ACCEPT-FD:3 PIPE)
for _ in {1..100}; do
    sleep 0.1
    if [[ ! -d "/proc/$PID" ]]; then
        # ACCEPT-FD is available since socat v1.8
        : "systemd-socket-activate or socat died. Maybe socat does not support ACCEPT-FD. Skipping test."
        break
    fi

    if [[ "$(cat /proc/"$PID"/comm || :)" =~ socat ]]; then
        assert_eq "$(echo -n bye | socat - 'TCP:localhost:1234')" bye
        tail --pid="$PID" -f /dev/null
        break
    fi
done

# --accept is not allowed with --now
(! systemd-socket-activate -l 1234 --accept --now cat)

# Multiple fds are not allowed with --inetd
(! systemd-socket-activate -l 1234 -l 4321 --inetd cat)
