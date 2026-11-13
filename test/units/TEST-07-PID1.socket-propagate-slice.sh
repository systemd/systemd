#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

at_exit() {
    systemctl stop inherit-slice.socket
    rm -f /run/systemd/system/inherit-slice{-client.service,@.service,.socket} /tmp/client.out
    systemctl daemon-reload
}

trap at_exit EXIT

cat >/run/systemd/system/inherit-slice.socket <<EOF
[Socket]
ListenStream=/run/inherit-slice.sk
Accept=yes
PropagateSlice=yes
EOF

cat >/run/systemd/system/inherit-slice@.service <<EOF
[Unit]
BindsTo=inherit-slice.socket
After=inherit-slice.socket

[Service]
ExecStartPre=echo waldo
ExecStart=sleep infinity
StandardOutput=socket
EOF

cat >/run/systemd/system/inherit-slice-client.service <<EOF
[Unit]
BindsTo=inherit-slice.socket
After=inherit-slice.socket

[Service]
Slice=system-test.slice
ExecStart=socat -U - UNIX-CONNECT:/run/inherit-slice.sk
StandardOutput=file:/tmp/client.out
EOF

systemctl daemon-reload
systemctl start inherit-slice-client.service

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

validate() {
	# First we check the dependency, i.e. the current value of Slice=
	systemctl show -P Slice 'inherit-slice@*.service' | grep system-test.slice >/dev/null

	# Then we check the cgroup the process actually runs under
	systemctl show -P ControlGroup 'inherit-slice@*.service' | grep system-test.slice >/dev/null
}

# Wait until we know a connection is established
waitfor /tmp/client.out

validate

systemctl daemon-reload
validate

systemctl daemon-reexec
validate
