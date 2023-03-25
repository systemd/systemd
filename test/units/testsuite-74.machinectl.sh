#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

# shellcheck source=test/units/assert.sh
. "$(dirname "$0")"/assert.sh

at_exit() {
    if [[ -v NSPAWN_NAME && -e "/var/lib/machines/$NSPAWN_NAME" ]]; then
        rm -fvr "/var/lib/machines/$NSPAWN_NAME" "/etc/systemd/nspawn/$NSPAWN_NAME" "new"
    fi

    return 0
}

trap at_exit EXIT

export NSPAWN_NAME="machinectl-test-$RANDOM.nspawn"
cat >"/var/lib/machines/$NSPAWN_NAME" <<\EOF
[Exec]
Boot=true
EOF

EDITOR='true' script -ec 'machinectl edit "$NSPAWN_NAME"' /dev/null
[ -f "/etc/systemd/nspawn/$NSPAWN_NAME" ]
cmp "/var/lib/machines/$NSPAWN_NAME" "/etc/systemd/nspawn/$NSPAWN_NAME"

cat >new <<\EOF
[Exec]
Boot=false
EOF

script -ec 'machinectl cat "$PWD/new"' /dev/null

EDITOR='mv new' script -ec 'machinectl edit "$NSPAWN_NAME"' /dev/null
printf '%s\n' '[Exec]' 'Boot=false' | cmp - "/etc/systemd/nspawn/$NSPAWN_NAME"
