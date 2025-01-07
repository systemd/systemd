#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

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
            systemd-analyze log-level info
            exit 1
        fi
        timeout=$((timeout - 1))
        sleep 1
        state=$(systemctl show "$service" --property=ActiveState --value)
    done
}

systemd-analyze log-level debug

cat >/run/systemd/system/testservice-failure-68.service <<EOF
[Unit]
OnFailure=testservice-failure-exit-handler-68.service

[Service]
ExecStart=false
EOF

cat >/run/systemd/system/testservice-failure-68-template.service <<EOF
[Unit]
OnFailure=testservice-failure-exit-handler-68-template@%n.service

[Service]
ExecStart=false
EOF

cat >/run/systemd/system/testservice-success-68.service <<EOF
[Unit]
OnSuccess=testservice-success-exit-handler-68.service

[Service]
ExecStart=true
EOF

cat >/run/systemd/system/testservice-success-68-template.service <<EOF
[Unit]
OnSuccess=testservice-success-exit-handler-68-template@%n.service

[Service]
ExecStart=true
EOF

cat >/run/systemd/system/testservice-success-and-failure-68.service <<EOF
[Unit]
OnSuccess=testservice-failure-exit-handler-68.service
OnFailure=testservice-failure-exit-handler-68.service

[Service]
ExecStart=true
EOF

# Script to check that when an OnSuccess= dependency fires, the correct
# MONITOR* env variables are passed.
cat >/tmp/check_on_success.sh <<"EOF"
#!/bin/sh

set -ex
env | sort
if [ "$MONITOR_SERVICE_RESULT" != "success" ]; then
    echo "MONITOR_SERVICE_RESULT was '$MONITOR_SERVICE_RESULT', expected 'success'"
    exit 1
fi

if [ "$MONITOR_EXIT_CODE" != "exited" ]; then
    echo "MONITOR_EXIT_CODE was '$MONITOR_EXIT_CODE', expected 'exited'"
    exit 1
fi

if [ "$MONITOR_EXIT_STATUS" != "0" ]; then
    echo "MONITOR_EXIT_STATUS was '$MONITOR_EXIT_STATUS', expected '0'"
    exit 1
fi

if [ -z "$MONITOR_INVOCATION_ID" ]; then
    echo "MONITOR_INVOCATION_ID unset"
    exit 1
fi

if [ "$MONITOR_UNIT" != "testservice-success-68.service" ] &&
   [ "$MONITOR_UNIT" != "testservice-success-68-template.service" ] &&
   [ "$MONITOR_UNIT" != "testservice-transient-success-68.service" ] &&
   [ "$MONITOR_UNIT" != "testservice-success-and-failure-68.service" ]; then

    echo "MONITOR_UNIT was '$MONITOR_UNIT', expected 'testservice[-transient]-success[-and-failure]-68[-template].service'"
    exit 1
fi

exit 0
EOF
chmod +x /tmp/check_on_success.sh

cat >/run/systemd/system/testservice-success-exit-handler-68.service <<EOF
[Service]
ExecStartPre=/tmp/check_on_success.sh
ExecStart=/tmp/check_on_success.sh
EOF

cp /run/systemd/system/testservice-success-exit-handler-68.service \
   /run/systemd/system/testservice-transient-success-exit-handler-68.service

# Template version.
cat >/run/systemd/system/testservice-success-exit-handler-68-template@.service <<EOF
[Service]
ExecStartPre=echo "triggered by %i"
ExecStartPre=/tmp/check_on_success.sh
ExecStart=/tmp/check_on_success.sh
EOF

# Script to check that when an OnFailure= dependency fires, the correct
# MONITOR* env variables are passed.
cat >/tmp/check_on_failure.sh <<"EOF"
#!/bin/sh

set -ex
env | sort
if [ "$MONITOR_SERVICE_RESULT" != "exit-code" ]; then
    echo "MONITOR_SERVICE_RESULT was '$MONITOR_SERVICE_RESULT', expected 'exit-code'"
    exit 1
fi

if [ "$MONITOR_EXIT_CODE" != "exited" ]; then
    echo "MONITOR_EXIT_CODE was '$MONITOR_EXIT_CODE', expected 'exited'"
    exit 1
fi

if [ "$MONITOR_EXIT_STATUS" != "1" ]; then
    echo "MONITOR_EXIT_STATUS was '$MONITOR_EXIT_STATUS', expected '1'"
    exit 1
fi

if [ -z "$MONITOR_INVOCATION_ID" ]; then
    echo "MONITOR_INVOCATION_ID unset"
    exit 1
fi

if [ "$MONITOR_UNIT" != "testservice-failure-68.service" ] &&
   [ "$MONITOR_UNIT" != "testservice-failure-68-template.service" ] &&
   [ "$MONITOR_UNIT" != "testservice-transient-failure-68.service" ]; then

    echo "MONITOR_UNIT was '$MONITOR_UNIT', expected 'testservice[-transient]-failure-68[-template].service'"
    exit 1
fi

exit 0
EOF
chmod +x /tmp/check_on_failure.sh


cat >/run/systemd/system/testservice-failure-exit-handler-68.service <<EOF
[Service]
# repeat the check to make sure that values are set correctly on repeated invocations
Type=oneshot
ExecStartPre=/tmp/check_on_failure.sh
ExecStartPre=/tmp/check_on_failure.sh
ExecStart=/tmp/check_on_failure.sh
ExecStart=/tmp/check_on_failure.sh
ExecStartPost=test -z '$MONITOR_SERVICE_RESULT'
EOF

cp /run/systemd/system/testservice-failure-exit-handler-68.service \
   /run/systemd/system/testservice-transient-failure-exit-handler-68.service

# Template version.
cat >/run/systemd/system/testservice-failure-exit-handler-68-template@.service <<EOF
[Service]
Type=oneshot
ExecStartPre=echo "triggered by %i"
ExecStartPre=/tmp/check_on_failure.sh
ExecStartPre=/tmp/check_on_failure.sh
ExecStart=/tmp/check_on_failure.sh
ExecStart=/tmp/check_on_failure.sh
ExecStartPost=test -z '$MONITOR_SERVICE_RESULT'
EOF

systemctl daemon-reload

: "-------I----------------------------------------------------"
systemctl start testservice-failure-68.service
wait_on_state_or_fail "testservice-failure-exit-handler-68.service" "inactive" "10"

: "-------II---------------------------------------------------"
systemctl start testservice-success-68.service
wait_on_state_or_fail "testservice-success-exit-handler-68.service" "inactive" "10"

# Test some transient units since these exit very quickly.
: "-------III--------------------------------------------------"
systemd-run --unit=testservice-transient-success-68 \
            --property=OnSuccess=testservice-transient-success-exit-handler-68.service \
            true
wait_on_state_or_fail "testservice-success-exit-handler-68.service" "inactive" "10"

: "-------IIII-------------------------------------------------"
systemd-run --unit=testservice-transient-failure-68 \
            --property=OnFailure=testservice-transient-failure-exit-handler-68.service \
            false
wait_on_state_or_fail "testservice-failure-exit-handler-68.service" "inactive" "10"

# Test template handlers too
: "-------V---------------------------------------------------"
systemctl start testservice-success-68-template.service
wait_on_state_or_fail "testservice-success-exit-handler-68-template@testservice-success-68-template.service.service" "inactive" "10"

: "-------VI----------------------------------------------------"
systemctl start testservice-failure-68-template.service
wait_on_state_or_fail "testservice-failure-exit-handler-68-template@testservice-failure-68-template.service.service" "inactive" "10"

# Test that monitor variables are set as long as OnSuccess= and OnFailure= dependant is the same
: "-------VII----------------------------------------------------"
systemctl start testservice-success-and-failure-68.service
wait_on_state_or_fail "testservice-success-exit-handler-68.service" "inactive" "10"

systemd-analyze log-level info

touch /testok
