#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

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
            systemd-analyze log-level info
            exit 1
        fi
        timeout=$((timeout - 1))
        sleep 1
        state=$(systemctl show "$service" --property=ActiveState --value)
    done
}

systemd-analyze log-level debug
systemd-analyze log-target console

# Trigger testservice-failure-exit-handler-68.service
cat >/run/systemd/system/testservice-failure-68.service <<EOF
[Unit]
Description=TEST-68-PROPAGATE-EXIT-STATUS with OnFailure= trigger
OnFailure=testservice-failure-exit-handler-68.service

[Service]
ExecStart=/bin/bash -c "exit 1"
EOF

# Another service which triggers testservice-failure-exit-handler-68.service
cat >/run/systemd/system/testservice-failure-68-additional.service <<EOF
[Unit]
Description=TEST-68-PROPAGATE-EXIT-STATUS Additonal service with OnFailure= trigger
OnFailure=testservice-failure-exit-handler-68.service

[Service]
ExecStart=/bin/bash -c "exit 1"
EOF

# Trigger testservice-failure-exit-handler-multi-68.service, this is the first
# of 2 services which trigger the same OnFailure= dependency. This let's us test
# job merging.
cat >/run/systemd/system/testservice-failure-68-multi0.service <<EOF
[Unit]
Description=TEST-68-PROPAGATE-EXIT-STATUS with OnFailure= trigger, multi 0
OnFailure=testservice-failure-exit-handler-multi-68.service

[Service]
ExecStart=/bin/bash -c "exit 1"
EOF

# Trigger testservice-failure-exit-handler-multi-68.service, this is the second
# of 2 services which trigger the same OnFailure= dependency. This let's us test
# job merging.
cat >/run/systemd/system/testservice-failure-68-multi1.service <<EOF
[Unit]
Description=TEST-68-PROPAGATE-EXIT-STATUS with OnFailure= trigger, multi 1
OnFailure=testservice-failure-exit-handler-multi-68.service

[Service]
ExecStart=/bin/bash -c "exit 1"
EOF

# Trigger testservice-success-exit-handler-68.service
cat >/run/systemd/system/testservice-success-68.service <<EOF
[Unit]
Description=TEST-68-PROPAGATE-EXIT-STATUS with OnSuccess= trigger
OnSuccess=testservice-success-exit-handler-68.service

[Service]
ExecStart=/bin/bash -c "exit 0"
EOF

# Trigger testservice-success-exit-handler-68.service
cat >/run/systemd/system/testservice-success-68-additional.service <<EOF
[Unit]
Description=TEST-68-PROPAGATE-EXIT-STATUS Addition service with OnSuccess= trigger
OnSuccess=testservice-success-exit-handler-68.service

[Service]
ExecStart=/bin/bash -c "exit 0"
EOF

# Trigger testservice-success-exit-handler-multi-68.service, this is the first
# of 2 services which trigger the same OnSuccess= dependency. This let's us test
# job merging.
cat >/run/systemd/system/testservice-success-68-multi0.service <<EOF
[Unit]
Description=TEST-68-PROPAGATE-EXIT-STATUS with OnSuccess= trigger, multi 0
OnSuccess=testservice-success-exit-handler-multi-68.service

[Service]
ExecStart=/bin/bash -c "exit 0"
EOF

# Trigger testservice-success-exit-handler-multi-68.service, this is the second
# of 2 services which trigger the same OnSuccess= dependency. This let's us test
# job merging.
cat >/run/systemd/system/testservice-success-68-multi1.service <<EOF
[Unit]
Description=TEST-68-PROPAGATE-EXIT-STATUS with OnSuccess= trigger, multi 1
OnSuccess=testservice-success-exit-handler-multi-68.service

[Service]
ExecStart=/bin/bash -c "exit 0"
EOF

# Script to check that when an OnSuccess= dependency fires, the correct
# MONITOR* env variables are passed.
cat >/tmp/check_on_success_single.sh <<EOF
#!/usr/bin/env bash

set -ex

IFS=',' read -ra METADATA <<< "\$MONITOR_METADATA"
IFS='=' read -ra SERVICE_RESULT <<< "\${METADATA[0]}"
SERVICE_RESULT=\${SERVICE_RESULT[1]}
IFS='=' read -ra EXIT_CODE <<< "\${METADATA[1]}"
EXIT_CODE=\${EXIT_CODE[1]}
IFS='=' read -ra EXIT_STATUS <<< "\${METADATA[2]}"
EXIT_STATUS=\${EXIT_STATUS[1]}
IFS='=' read -ra INVOCATION_ID <<< "\${METADATA[3]}"
INVOCATION_ID=\${INVOCATION_ID[1]}
IFS='=' read -ra UNIT <<< "\${METADATA[4]}"
UNIT=\${UNIT[1]}

if [ "\$SERVICE_RESULT" != "success" ]; then
    echo 'SERVICE_RESULT was "\$SERVICE_RESULT", expected "success"';
    exit 1;
fi

if [ "\$EXIT_CODE" != "exited" ]; then
    echo 'EXIT_CODE was "\$EXIT_CODE", expected "exited"';
    exit 1;
fi

if [ "\$EXIT_STATUS" != "0" ]; then
    echo 'EXIT_STATUS was "\$EXIT_STATUS", expected "0"';
    exit 1;
fi

if [ -z "\$INVOCATION_ID" ]; then
    echo 'INVOCATION_ID unset';
    exit 1;
fi

if [[ "\$UNIT" != "testservice-success-68.service" && "\$UNIT" != "testservice-success-68-additional.service" && "\$UNIT" != "testservice-transient-success-68.service" ]]; then
    echo 'UNIT was "\$UNIT", expected "testservice-success-68{-additional,-transient}.service"';
    exit 1;
fi

exit 0;
EOF
chmod +x /tmp/check_on_success_single.sh

# Script to check that when an OnSuccess= dependency fires, the correct
# MONITOR* env variables are passed. This script handles the case where
# multiple services triggered the unit that calls this script. In this
# case we need to check the MONITOR_METADATA for 2 service details.
cat >/tmp/check_on_success_multi.sh <<EOF
#!/usr/bin/env bash

set -ex

INSTANCE=0
IFS=';' read -ra ALL_SERVICE_MD <<< "\$MONITOR_METADATA"
for SERVICE_MD in "\${ALL_SERVICE_MD[@]}"; do
    IFS=',' read -ra METADATA <<< "\$SERVICE_MD"
    IFS='=' read -ra SERVICE_RESULT <<< "\${METADATA[0]}"
    SERVICE_RESULT=\${SERVICE_RESULT[1]}
    IFS='=' read -ra EXIT_CODE <<< "\${METADATA[1]}"
    EXIT_CODE=\${EXIT_CODE[1]}
    IFS='=' read -ra EXIT_STATUS <<< "\${METADATA[2]}"
    EXIT_STATUS=\${EXIT_STATUS[1]}
    IFS='=' read -ra INVOCATION_ID <<< "\${METADATA[3]}"
    INVOCATION_ID=\${INVOCATION_ID[1]}
    IFS='=' read -ra UNIT <<< "\${METADATA[4]}"
    UNIT=\${UNIT[1]}

    if [ "\$SERVICE_RESULT" != "success" ]; then
        echo 'SERVICE_RESULT was "\$SERVICE_RESULT", expected "success"';
        exit 1;
    fi

    if [ "\$EXIT_CODE" != "exited" ]; then
        echo 'EXIT_CODE was "\$EXIT_CODE", expected "exited"';
        exit 1;
    fi

    if [ "\$EXIT_STATUS" != "0" ]; then
        echo 'EXIT_STATUS was "\$EXIT_STATUS", expected "0"';
        exit 1;
    fi

    if [ -z "\$INVOCATION_ID" ]; then
        echo 'INVOCATION_ID unset';
        exit 1;
    fi

    EXPECTED_UNIT="testservice-success-68-multi\${INSTANCE}.service"
    INSTANCE=\$((INSTANCE + 1))

    if [ "\$UNIT" != "\$EXPECTED_UNIT" ]; then
        echo 'UNIT was "\$UNIT", expected "\$EXPECTED_UNIT"';
        exit 1;
    fi
done

exit 0;
EOF
chmod +x /tmp/check_on_success_multi.sh

# Handle testservice-failure-exit-handler-68.service exiting with success.
cat >/run/systemd/system/testservice-success-exit-handler-68.service <<EOF
[Unit]
Description=TEST-68-PROPAGATE-EXIT-STATUS handle service exiting in success

[Service]
ExecStartPre=/tmp/check_on_success_single.sh
ExecStart=/tmp/check_on_success_single.sh
EOF

# Handle testservice-success-exit-handler-68-multiN.service exiting with failure.
cat >/run/systemd/system/testservice-success-exit-handler-multi-68.service <<EOF
[Unit]
Description=TEST-68-PROPAGATE-EXIT-STATUS handle service exiting in failure

[Service]
ExecStartPre=/tmp/check_on_success_multi.sh
ExecStart=/tmp/check_on_success_multi.sh
EOF

# Script to check that when an OnFailure= dependency fires, the correct
# MONITOR* env variables are passed.
cat >/tmp/check_on_failure_single.sh <<EOF
#!/usr/bin/env bash

set -ex

IFS=',' read -ra METADATA <<< "\$MONITOR_METADATA"
IFS='=' read -ra SERVICE_RESULT <<< "\${METADATA[0]}"
SERVICE_RESULT=\${SERVICE_RESULT[1]}
IFS='=' read -ra EXIT_CODE <<< "\${METADATA[1]}"
EXIT_CODE=\${EXIT_CODE[1]}
IFS='=' read -ra EXIT_STATUS <<< "\${METADATA[2]}"
EXIT_STATUS=\${EXIT_STATUS[1]}
IFS='=' read -ra INVOCATION_ID <<< "\${METADATA[3]}"
INVOCATION_ID=\${INVOCATION_ID[1]}
IFS='=' read -ra UNIT <<< "\${METADATA[4]}"
UNIT=\${UNIT[1]}

if [ "\$SERVICE_RESULT" != "exit-code" ]; then
    echo 'SERVICE_RESULT was "\$SERVICE_RESULT", expected "success"';
    exit 1;
fi

if [ "\$EXIT_CODE" != "exited" ]; then
    echo 'EXIT_CODE was "\$EXIT_CODE", expected "exited"';
    exit 1;
fi

if [ "\$EXIT_STATUS" != "1" ]; then
    echo 'EXIT_STATUS was "\$EXIT_STATUS", expected "1"';
    exit 1;
fi

if [ -z "\$INVOCATION_ID" ]; then
    echo 'INVOCATION_ID unset';
    exit 1;
fi

if [[ "\$UNIT" != "testservice-failure-68.service" && "\$UNIT" != "testservice-failure-68-additional.service" && "\$UNIT" != "testservice-transient-failure-68.service" ]]; then
    echo 'UNIT was "\$UNIT", expected "testservice-failure-68{-additional,-transient}.service"';
    exit 1;
fi

exit 0;
EOF
chmod +x /tmp/check_on_failure_single.sh

# Script to check that when an OnFailure= dependency fires, the correct
# MONITOR* env variables are passed. This script handles the case where
# multiple services triggered the unit that calls this script. In this
# case we need to check the MONITOR_METADATA for 2 service details.
cat >/tmp/check_on_failure_multi.sh <<EOF
#!/usr/bin/env bash

set -ex

INSTANCE=0
IFS=';' read -ra ALL_SERVICE_MD <<< "\$MONITOR_METADATA"
for SERVICE_MD in "\${ALL_SERVICE_MD[@]}"; do
    IFS=',' read -ra METADATA <<< "\$SERVICE_MD"
    IFS='=' read -ra SERVICE_RESULT <<< "\${METADATA[0]}"
    SERVICE_RESULT=\${SERVICE_RESULT[1]}
    IFS='=' read -ra EXIT_CODE <<< "\${METADATA[1]}"
    EXIT_CODE=\${EXIT_CODE[1]}
    IFS='=' read -ra EXIT_STATUS <<< "\${METADATA[2]}"
    EXIT_STATUS=\${EXIT_STATUS[1]}
    IFS='=' read -ra INVOCATION_ID <<< "\${METADATA[3]}"
    INVOCATION_ID=\${INVOCATION_ID[1]}
    IFS='=' read -ra UNIT <<< "\${METADATA[4]}"
    UNIT=\${UNIT[1]}

    if [ "\$SERVICE_RESULT" != "exit-code" ]; then
        echo 'SERVICE_RESULT was "\$SERVICE_RESULT", expected "exit-code"';
        exit 1;
    fi

    if [ "\$EXIT_CODE" != "exited" ]; then
        echo 'EXIT_CODE was "\$EXIT_CODE", expected "exited"';
        exit 1;
    fi

    if [ "\$EXIT_STATUS" != "1" ]; then
        echo 'EXIT_STATUS was "\$EXIT_STATUS", expected "1"';
        exit 1;
    fi

    if [ -z "\$INVOCATION_ID" ]; then
        echo 'INVOCATION_ID unset';
        exit 1;
    fi

    EXPECTED_UNIT="testservice-failure-68-multi\${INSTANCE}.service"
    INSTANCE=\$((INSTANCE + 1))

    if [ "\$UNIT" != "\$EXPECTED_UNIT" ]; then
        echo 'UNIT was "\$UNIT", expected "\$EXPECTED_UNIT"';
        exit 1;
    fi
done

exit 0;
EOF
chmod +x /tmp/check_on_failure_multi.sh


# Handle testservice-failure-exit-handler-68.service exiting with failure.
cat >/run/systemd/system/testservice-failure-exit-handler-68.service <<EOF
[Unit]
Description=TEST-68-PROPAGATE-EXIT-STATUS handle service exiting in failure

[Service]
ExecStartPre=/tmp/check_on_failure_single.sh
ExecStart=/tmp/check_on_failure_single.sh
EOF

# Handle testservice-failure-exit-handler-68.service exiting with failure.
cat >/run/systemd/system/testservice-failure-exit-handler-multi-68.service <<EOF
[Unit]
Description=TEST-68-PROPAGATE-EXIT-STATUS handle service exiting in failure

[Service]
ExecStartPre=/tmp/check_on_failure_multi.sh
ExecStart=/tmp/check_on_failure_multi.sh
EOF

systemctl daemon-reload

systemctl start testservice-failure-68.service
wait_on_state_or_fail "testservice-failure-exit-handler-68.service" "inactive" "10"
systemctl start testservice-failure-68-additional.service
wait_on_state_or_fail "testservice-failure-exit-handler-68.service" "inactive" "10"
systemctl start testservice-success-68.service
wait_on_state_or_fail "testservice-success-exit-handler-68.service" "inactive" "10"
systemctl start testservice-success-68-additional.service
wait_on_state_or_fail "testservice-success-exit-handler-68.service" "inactive" "10"

# Test some transient units since these exit very quickly.
systemd-run --unit=testservice-transient-success-68 --property=OnSuccess=testservice-success-exit-handler-68.service /bin/bash -c "exit 0;"
wait_on_state_or_fail "testservice-success-exit-handler-68.service" "inactive" "10"
systemd-run --unit=testservice-transient-failure-68 --property=OnFailure=testservice-failure-exit-handler-68.service /bin/bash -c "exit 1;"
wait_on_state_or_fail "testservice-failure-exit-handler-68.service" "inactive" "10"

# Run both services at the same time, this sometimes causes their start jobs to
# merge. In this case the MONITOR_METADATA environment contains exit details for
# both services and thus needs some more complex parsing.
systemctl start testservice-failure-68-multi0.service testservice-failure-68-multi1.service --no-block
wait_on_state_or_fail "testservice-failure-exit-handler-multi-68.service" "inactive" "10"
systemctl start testservice-success-68-multi0.service testservice-success-68-multi1.service --no-block
wait_on_state_or_fail "testservice-success-exit-handler-multi-68.service" "inactive" "10"

systemd-analyze log-level info
echo OK >/testok

exit 0
