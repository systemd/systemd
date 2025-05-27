#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

systemd-socket-activate -l 1234 --accept --inetd cat &
CAT_PID="$!"
sleep 1

assert_eq "$(echo -n 'hello' | socat - 'TCP:localhost:1234')" 'hello'

systemd-socket-activate -l 4321 --now -- \
    /usr/lib/systemd/systemd-socket-proxyd localhost:1234
PROXY_PID="$!"
sleep 1

assert_eq "$(echo -n 'bye' | socat - 'TCP:localhost:4321')" 'bye'
kill "$PROXY_PID" "$CAT_PID"

# --accept is not allowed with --now
(! systemd-socket-activate -l 1234 --accept --now cat)

# Multiple fds are not allowed with --inetd
(! systemd-socket-activate -l 1234 -l 4321 --inetd cat)
