#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

rm -f /test.log

TESTLOG=/test.log.XXXXXXXX

function wait_for()
{
    local service="${1:-wait_for: missing service argument}"
    local result="${2:-success}"
    local time="${3:-45}"

    while [[ ! -f /${service}.terminated && ! -f /${service}.success && $time -gt 0 ]]; do
        sleep 1
        time=$((time - 1))
    done

    if [[ ! -f /${service}.${result} ]]; then
        journalctl -u "${service/_/-}.service" >>"$TESTLOG"
    fi
}

function wait_for_timeout()
{
    local unit="$1"
    local time="$2"

    while [[ $time -gt 0 ]]; do
        if [[ "$(systemctl show --property=Result "$unit")" == "Result=timeout" ]]; then
            return 0
        fi

        sleep 1
        time=$((time - 1))
    done

    journalctl -u "$unit" >>"$TESTLOG"

    return 1
}

# This checks all stages, start, runtime and stop, can be extended by
# EXTEND_TIMEOUT_USEC

wait_for success_all

# These check that EXTEND_TIMEOUT_USEC that occurs at greater than the
# extend timeout interval but less then the stage limit (TimeoutStartSec,
# RuntimeMaxSec, TimeoutStopSec) still succeed.

wait_for success_start
wait_for success_runtime
wait_for success_stop

# These ensure that EXTEND_TIMEOUT_USEC will still timeout in the
# appropriate stage, after the stage limit, when the EXTEND_TIMEOUT_USEC
# message isn't sent within the extend timeout interval.

wait_for fail_start startfail
wait_for fail_stop stopfail
wait_for fail_runtime runtimefail

# These ensure that RuntimeMaxSec is honored for scope and service units
# when they are created.
runtime_max_sec=5

systemd-run \
    --property=RuntimeMaxSec=${runtime_max_sec}s \
    -u runtime-max-sec-test-1.service \
    /usr/bin/sh -c "while true; do sleep 1; done"
wait_for_timeout runtime-max-sec-test-1.service $((runtime_max_sec + 2))

systemd-run \
    --property=RuntimeMaxSec=${runtime_max_sec}s \
    --scope \
    -u runtime-max-sec-test-2.scope \
    /usr/bin/sh -c "while true; do sleep 1; done" &
wait_for_timeout runtime-max-sec-test-2.scope $((runtime_max_sec + 2))

# These ensure that RuntimeMaxSec is honored for scope and service
# units if the value is changed and then the manager is reloaded.
systemd-run \
    -u runtime-max-sec-test-3.service \
    /usr/bin/sh -c "while true; do sleep 1; done"
mkdir -p /etc/systemd/system/runtime-max-sec-test-3.service.d/
cat > /etc/systemd/system/runtime-max-sec-test-3.service.d/override.conf << EOF
[Service]
RuntimeMaxSec=${runtime_max_sec}s
EOF
systemctl daemon-reload
wait_for_timeout runtime-max-sec-test-3.service $((runtime_max_sec + 2))

systemd-run \
    --scope \
    -u runtime-max-sec-test-4.scope \
    /usr/bin/sh -c "while true; do sleep 1; done" &

# Wait until the unit is running to avoid race with creating the override.
until systemctl is-active runtime-max-sec-test-4.scope; do
    sleep 1
done
mkdir -p /etc/systemd/system/runtime-max-sec-test-4.scope.d/
cat > /etc/systemd/system/runtime-max-sec-test-4.scope.d/override.conf << EOF
[Scope]
RuntimeMaxSec=${runtime_max_sec}s
EOF
systemctl daemon-reload
wait_for_timeout runtime-max-sec-test-4.scope $((runtime_max_sec + 2))

if [[ -f "$TESTLOG" ]]; then
    # no mv
    cp "$TESTLOG" /test.log
    exit 1
fi

touch /testok
exit 0
