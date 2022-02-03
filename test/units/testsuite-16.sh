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

if [[ -f "$TESTLOG" ]]; then
    # no mv
    cp "$TESTLOG" /test.log
    exit 1
fi

touch /testok
exit 0
