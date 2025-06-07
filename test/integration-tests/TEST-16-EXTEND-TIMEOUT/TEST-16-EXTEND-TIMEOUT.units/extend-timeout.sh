#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# sleep interval (seconds)
sleep_interval="${sleep_interval:-1}"
# extend_timeout_interval second(s)
extend_timeout_interval="${extend_timeout_interval:-1}"
# number of sleep_intervals before READY=1
start_intervals="${start_intervals:-10}"
# number of sleep_intervals before exiting
stop_intervals="${stop_intervals:-10}"
# run intervals, number of sleep_intervals to run
run_intervals="${run_intervals:-7}"

# We convert to usec
extend_timeout_interval=$((extend_timeout_interval * 1000000))

# shellcheck disable=SC2064
trap "{ touch /${SERVICE}.terminated; exit 1; }" SIGTERM SIGABRT

rm -f "/${SERVICE}".*
touch "/${SERVICE}.startfail"

systemd-notify EXTEND_TIMEOUT_USEC="$extend_timeout_interval"
while [[ $start_intervals -gt 0 ]]
do
    sleep "$sleep_interval"
    start_intervals=$((start_intervals - 1))
    systemd-notify EXTEND_TIMEOUT_USEC="$extend_timeout_interval"
done

systemd-notify --ready --status="Waiting for your request"

touch "/${SERVICE}.runtimefail"
rm "/${SERVICE}.startfail"

systemd-notify EXTEND_TIMEOUT_USEC="$extend_timeout_interval"
while [[ $run_intervals -gt 0 ]]
do
    sleep "$sleep_interval"
    run_intervals=$((run_intervals - 1))
    systemd-notify EXTEND_TIMEOUT_USEC="$extend_timeout_interval"
done

systemd-notify STOPPING=1

touch "/${SERVICE}.stopfail"
rm "/${SERVICE}.runtimefail"

systemd-notify EXTEND_TIMEOUT_USEC="$extend_timeout_interval"
while [[ $stop_intervals -gt 0 ]]
do
    sleep "$sleep_interval"
    stop_intervals=$((stop_intervals - 1))
    systemd-notify EXTEND_TIMEOUT_USEC="$extend_timeout_interval"
done

touch "/${SERVICE}.success"
rm "/${SERVICE}.stopfail"

exit 0
