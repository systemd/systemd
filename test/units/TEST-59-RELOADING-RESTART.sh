#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

fail() {
    systemd-analyze log-level info
    exit 1
}

# Wait for a service to enter a state within a timeout period, if it doesn't
# enter the desired state within the timeout period then this function will
# exit the test case with a non zero exit code.
wait_on_state_or_fail() {
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
ExecStart=bash -c "systemd-notify --ready; systemd-notify RELOADING=1; sleep 1; exit 1"
EOF

cat >/run/systemd/system/testservice-fail-restart-59.service <<EOF
[Unit]
Description=TEST-59-RELOADING-RESTART Restart=on-failure

[Service]
Type=notify
ExecStart=bash -c "systemd-notify --ready; systemd-notify RELOADING=1; sleep 1; exit 1"
Restart=on-failure
StartLimitBurst=1
EOF


cat >/run/systemd/system/testservice-abort-restart-59.service <<EOF
[Unit]
Description=TEST-59-RELOADING-RESTART Restart=on-abort

[Service]
Type=notify
ExecStart=bash -c "systemd-notify --ready; systemd-notify RELOADING=1; sleep 5; exit 1"
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

# Test that rate-limiting daemon-reload works
mkdir -p /run/systemd/system.conf.d/
cat >/run/systemd/system.conf.d/50-test-59-reload.conf <<EOF
[Manager]
ReloadLimitIntervalSec=9
ReloadLimitBurst=3
EOF

# Pick up the new config
systemctl daemon-reload

# The timeout will hit (and the test will fail) if the reloads are not rate-limited
timeout 15 bash -c 'while systemctl daemon-reload --no-block; do true; done'

# Rate limit should reset after 9s
sleep 10

systemctl daemon-reload

# Same test for reexec, but we wait here
timeout 15 bash -c 'while systemctl daemon-reexec; do true; done'

# Rate limit should reset after 9s
sleep 10

systemctl daemon-reexec

# Let's now test the notify-reload logic

cat >/run/notify-reload-test.sh <<EOF
#!/usr/bin/env bash
set -eux
set -o pipefail

EXIT_STATUS=88
LEAVE=0

function reload() {
    systemd-notify --reloading --status="Adding 11 to exit status"
    EXIT_STATUS=\$((EXIT_STATUS + 11))
    systemd-notify --ready --status="Back running"
}

function leave() {
    systemd-notify --stopping --status="Adding 7 to exit status"
    EXIT_STATUS=\$((EXIT_STATUS + 7))
    LEAVE=1
    return 0
}

trap reload SIGHUP
trap leave SIGTERM

systemd-notify --ready
systemd-notify --status="Running now"

while [ \$LEAVE = 0 ] ; do
    sleep 1
done

systemd-notify --status="Adding 3 to exit status"
EXIT_STATUS=\$((EXIT_STATUS + 3))
exit \$EXIT_STATUS
EOF

chmod +x /run/notify-reload-test.sh

systemd-analyze log-level debug

systemd-run --unit notify-reload-test -p Type=notify-reload -p KillMode=process /run/notify-reload-test.sh
systemctl reload notify-reload-test
systemctl stop notify-reload-test

test "$(systemctl show -p ExecMainStatus --value notify-reload-test)" = 109

systemctl reset-failed notify-reload-test
rm /run/notify-reload-test.sh

systemd-analyze log-level info

# Ensure that, with system log level info, we get debug level messages when a unit fails to start and is
# restarted with RestartMode=debug
cat >/run/systemd/system/testservice-fail-restart-debug-59.service <<EOF
[Unit]
Description=TEST-59-RELOADING-RESTART Restart=on-failure RestartMode=debug

[Service]
ExecStart=echo hello
Restart=on-failure
RestartMode=debug
StartLimitBurst=3
MountAPIVFS=yes
BindPaths=/nonexistent-debug-59
EOF

systemctl daemon-reload
systemctl start testservice-fail-restart-debug-59.service
wait_on_state_or_fail "testservice-fail-restart-debug-59.service" "failed" "15"
journalctl --sync
journalctl -b | grep -q "Failed to follow symlinks on /nonexistent-debug-59: No such file or directory"

touch /testok
