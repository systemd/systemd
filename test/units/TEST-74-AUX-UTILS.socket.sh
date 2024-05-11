#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

at_exit() {
    systemctl stop per-source-limit.socket
    rm -f /run/systemd/system/per-source-limit{@.service,.socket} /run/foo.conn{1..4}
    systemctl daemon-reload
}

trap at_exit EXIT

cat >/run/systemd/system/per-source-limit.socket <<EOF
[Socket]
ListenStream=/run/per-source-limit.sk
MaxConnectionsPerSource=2
Accept=yes
EOF

cat >/run/systemd/system/per-source-limit@.service <<EOF
[Unit]
BindsTo=per-source-limit.socket
After=per-source-limit.socket

[Service]
ExecStartPre=echo waldo
ExecStart=sleep infinity
StandardOutput=socket
EOF

systemctl daemon-reload
systemctl start per-source-limit.socket
systemctl status per-source-limit.socket

# So these two should take up the first two connection slots
socat -U - UNIX-CONNECT:/run/per-source-limit.sk | tee /tmp/foo.conn1 &
J1="$!"
socat -U - UNIX-CONNECT:/run/per-source-limit.sk | tee /tmp/foo.conn2 &
J2="$!"

waitfor() {
    local file="${1:?}"

    for _ in {0..20}; do
        if grep -q waldo "$file"; then
            return 0
        fi

        sleep .5
    done

    echo >&2 "Timeout while waiting for the expected output"
    return 1
}

# Wait until the word "waldo" shows in the output files
waitfor /tmp/foo.conn1
waitfor /tmp/foo.conn2

# The next connection should fail, because the limit is hit
socat -U - UNIX-CONNECT:/run/per-source-limit.sk | tee /tmp/foo.conn3 &
J3="$!"

# But this one should work, because done under a different UID
setpriv --reuid=1 socat -U - UNIX-CONNECT:/run/per-source-limit.sk | tee /tmp/foo.conn4 &
J4="$!"

waitfor /tmp/foo.conn4

# The third job should fail quickly, wait for it
wait "$J3"

# The other jobs will hang forever, since we run "sleep infinity" on the server side. Let's kill the jobs now.
kill "$J1"
kill "$J2"
kill "$J4"

# The 3rd connection should not have seen "waldo", since it should have been refused too early
(! grep -q "waldo" /tmp/foo.conn3 )
