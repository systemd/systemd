#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

fail () {
    systemd-analyze log-level info
    exit 1
}

# Wait for a service to enter a state within a timeout period, if it doesn't
# enter the desired state within the timeout period then this function will
# exit the test case with a non zero exit code.
wait_on_state_or_fail () {
    service=$1
    expected_state=$2
    timeout=$3

    state=$(systemctl show "$service" --property=ActiveState --value)
    while [ "$state" != "$expected_state" ]; do
        if [ "$timeout" = "0" ]; then
            fail
        fi
        timeout=$((timeout - 1))
        sleep 1
        state=$(systemctl show "$service" --property=ActiveState --value)
    done
}

systemd-analyze log-level debug


cat >/run/systemd/system/testservice-fail-59.service <<EOF
[Unit]
Description=TEST-59-RELOADING-RESTART Normal exit

[Service]
Type=notify
ExecStart=/bin/bash -c "systemd-notify --ready; systemd-notify RELOADING=1; sleep 1; exit 1"
EOF

cat >/run/systemd/system/testservice-fail-restart-59.service <<EOF
[Unit]
Description=TEST-59-RELOADING-RESTART Restart=on-failure

[Service]
Type=notify
ExecStart=/bin/bash -c "systemd-notify --ready; systemd-notify RELOADING=1; sleep 1; exit 1"
Restart=on-failure
StartLimitBurst=1
EOF


cat >/run/systemd/system/testservice-abort-restart-59.service <<EOF
[Unit]
Description=TEST-59-RELOADING-RESTART Restart=on-abort

[Service]
Type=notify
ExecStart=/bin/bash -c "systemd-notify --ready; systemd-notify RELOADING=1; sleep 5; exit 1"
Restart=on-abort
EOF

systemctl daemon-reload

# This service sends a RELOADING=1 message then exits before it sends a
# READY=1. Ensure it enters failed state and does not linger in reloading
# state.
systemctl start testservice-fail-59.service
wait_on_state_or_fail "testservice-fail-59.service" "failed" "30"

# This service sends a RELOADING=1 message then exits before it sends a
# READY=1. It should automatically restart on failure. Ensure it enters failed
# state and does not linger in reloading state.
systemctl start testservice-fail-restart-59.service
wait_on_state_or_fail "testservice-fail-restart-59.service" "failed" "30"

# This service sends a RELOADING=1 message then exits before it sends a
# READY=1. It should automatically restart on abort. It will sleep for 5s
# to allow us to send it a SIGABRT. Ensure the service enters the failed state
# and does not linger in reloading state.
systemctl start testservice-abort-restart-59.service
systemctl --signal=SIGABRT kill testservice-abort-restart-59.service
wait_on_state_or_fail "testservice-abort-restart-59.service" "failed" "30"

systemd-analyze log-level info

echo OK >/testok

exit 0
