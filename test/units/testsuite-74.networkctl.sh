#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

at_exit() {
    if [[ -v NETWORK_NAME && -e "/usr/lib/systemd/network/$NETWORK_NAME" ]]; then
        rm -fvr "/usr/lib/systemd/network/$NETWORK_NAME" "/etc/systemd/network/$NETWORK_NAME" "new" "+4"
    fi
}

trap at_exit EXIT

export NETWORK_NAME="networkctl-test-$RANDOM.network"
cat >"/usr/lib/systemd/network/$NETWORK_NAME" <<\EOF
[Match]
Name=test
EOF

networkctl cat "$NETWORK_NAME" | tail -n +2 | cmp - "/usr/lib/systemd/network/$NETWORK_NAME"

cat >new <<\EOF
[Match]
Name=test2
EOF

EDITOR='mv new' script -ec 'networkctl edit "$NETWORK_NAME"' /dev/null
printf '%s\n' '[Match]' 'Name=test2' | cmp - "/etc/systemd/network/$NETWORK_NAME"

cat >"+4" <<\EOF
[Network]
DHCP=yes
EOF

EDITOR='cp' script -ec 'networkctl edit "$NETWORK_NAME" --drop-in test' /dev/null
cmp "+4" "/etc/systemd/network/${NETWORK_NAME}.d/test.conf"

networkctl cat "$NETWORK_NAME" | grep '^# ' |
    cmp - <(printf '%s\n' "# /etc/systemd/network/$NETWORK_NAME" "# /etc/systemd/network/${NETWORK_NAME}.d/test.conf")
