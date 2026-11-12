#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh
# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

at_exit() {
    systemctl stop varlink-test-enqueue{,-2}.service varlink-test-slow.service varlink-test-reexec.service 2>/dev/null || true
    if [[ -n ${watcher_pid:-} ]]; then
        kill "$watcher_pid" 2>/dev/null || true
        wait "$watcher_pid" 2>/dev/null || true
    fi
    rm -f /run/systemd/system/varlink-test-enqueue{,-2}.service /run/systemd/system/varlink-test-slow.service /run/systemd/system/varlink-test-reexec.service
    rm -f /tmp/enqueue-notifications.json
    systemctl daemon-reload
}

testcase_transactions() {
    trap at_exit EXIT

    for unit in varlink-test-enqueue{,-2}.service; do
        cat >"/run/systemd/system/$unit" <<UNIT
[Service]
Type=oneshot
ExecStart=true
RemainAfterExit=yes
UNIT
    done
    systemctl daemon-reload

    # Non-streaming start with an explicit job mode.
    varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.EnqueueJob '{"names": ["varlink-test-enqueue.service"], "jobType": "start", "mode": "fail"}' | jq -e '.context and .runtime and .job.Id and .job.JobType == "start"'
    timeout 10 bash -c 'until systemctl is-active varlink-test-enqueue.service; do sleep 0.5; done'

    # Streaming restart waits for completion.
    varlinkctl call --collect /run/systemd/io.systemd.Manager io.systemd.Unit.EnqueueJob '{"names": ["varlink-test-enqueue.service"], "jobType": "restart", "notifyJobChanges": true}' | jq -e 'length > 1 and .[0].job.JobType == "restart" and .[-1].job.Result == "done" and .[-1].context and .[-1].runtime'
    systemctl is-active varlink-test-enqueue.service

    varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.EnqueueJob \
        '{"names":["varlink-test-enqueue.service"],"jobType":"stop","mode":null,"notifyJobChanges":null,"notifyUnitChanges":null}' \
        | jq -e '.job.Id and .job.JobType == "stop"'
    timeout 10 bash -c 'until systemctl show -P ActiveState varlink-test-enqueue.service | grep inactive >/dev/null; do sleep 0.5; done'

    # Multiple units share a transaction and receive one reply per job.
    varlinkctl call --collect /run/systemd/io.systemd.Manager io.systemd.Unit.EnqueueJob '{"names": ["varlink-test-enqueue.service", "varlink-test-enqueue-2.service"], "jobType": "start"}' | jq -e 'length == 2 and all(.[]; .context and .runtime and .job.Id) and ([.[].job.Unit] | sort == ["varlink-test-enqueue-2.service", "varlink-test-enqueue.service"])'
    timeout 10 bash -c 'until systemctl is-active varlink-test-enqueue.service; do sleep 0.5; done'
    timeout 10 bash -c 'until systemctl is-active varlink-test-enqueue-2.service; do sleep 0.5; done'
    systemctl stop varlink-test-enqueue{,-2}.service

    # Multiple replies require 'more'.
    (! varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.EnqueueJob '{"names": ["varlink-test-enqueue.service", "varlink-test-enqueue-2.service"], "jobType": "start"}')

    # A missing unit rejects the entire transaction.
    (! varlinkctl call --more /run/systemd/io.systemd.Manager io.systemd.Unit.EnqueueJob '{"names": ["varlink-test-enqueue.service", "non-existent.service"], "jobType": "start"}')
    (! systemctl is-active varlink-test-enqueue.service)

    # Notifications require 'more' and a single unit.
    (! varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.EnqueueJob '{"names": ["varlink-test-enqueue.service"], "jobType": "start", "notifyJobChanges": true}')
    (! varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.EnqueueJob '{"names": ["varlink-test-enqueue.service"], "jobType": "start", "notifyUnitChanges": true}')

    (! varlinkctl call --more /run/systemd/io.systemd.Manager io.systemd.Unit.EnqueueJob '{"names": ["varlink-test-enqueue.service", "varlink-test-enqueue-2.service"], "jobType": "start", "notifyJobChanges": true}')

    # Error cases
    (! varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.EnqueueJob '{"names": ["invalid-unit-name"], "jobType": "start"}')
    (! varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.EnqueueJob '{"names": [], "jobType": "start"}')
}

testcase_coalesced_watcher() {
    trap at_exit EXIT

    # Coalesced jobs must reject a second watcher.
    cat >/run/systemd/system/varlink-test-slow.service <<UNIT
[Service]
Type=oneshot
ExecStart=/usr/bin/sleep infinity
RemainAfterExit=yes
UNIT
    systemctl daemon-reload

    varlinkctl call --more /run/systemd/io.systemd.Manager io.systemd.Unit.EnqueueJob \
        '{"names": ["varlink-test-slow.service"], "jobType": "start", "notifyJobChanges": true}' >/dev/null 2>&1 &
    watcher_pid=$!

    # Wait for the first watcher to attach.
    timeout 10 bash -c 'until systemctl show -P ActiveState varlink-test-slow.service | grep activating >/dev/null; do sleep 0.5; done'

    set +o pipefail
    varlinkctl call --more /run/systemd/io.systemd.Manager io.systemd.Unit.EnqueueJob \
        '{"names": ["varlink-test-slow.service"], "jobType": "start", "notifyJobChanges": true}' |& grep "io.systemd.Unit.AlreadyBeingWatched"
    set -o pipefail

    systemctl stop varlink-test-slow.service
    wait "$watcher_pid" 2>/dev/null || true
    watcher_pid=
}

testcase_nop_subscription() {
    trap at_exit EXIT

    cat >/run/systemd/system/varlink-test-slow.service <<UNIT
[Service]
Type=oneshot
ExecStart=/usr/bin/sleep infinity
RemainAfterExit=yes
UNIT
    systemctl daemon-reload

    # Completing a NOP job must preserve the regular job's unit subscription.
    varlinkctl --json=short call --more /run/systemd/io.systemd.Manager io.systemd.Unit.EnqueueJob \
        '{"names": ["varlink-test-slow.service"], "jobType": "start", "notifyUnitChanges": true}' >/tmp/enqueue-notifications.json &
    watcher_pid=$!

    timeout 10 bash -c 'until systemctl show -P ActiveState varlink-test-slow.service | grep activating >/dev/null; do sleep 0.5; done'

    # The pending start job keeps the stream open; each line is a unit notification.
    sleep 1
    notifications=$(wc -l </tmp/enqueue-notifications.json)

    # NOP uses a separate job slot and completes immediately.
    varlinkctl call --more /run/systemd/io.systemd.Manager io.systemd.Unit.EnqueueJob \
        '{"names": ["varlink-test-slow.service"], "jobType": "nop", "notifyJobChanges": true}' >/dev/null

    # NOP removal must still trigger a unit notification.
    for _ in {1..20}; do
        [[ "$(wc -l </tmp/enqueue-notifications.json)" -gt "$notifications" ]] && break
        sleep 0.1
    done
    [[ "$(wc -l </tmp/enqueue-notifications.json)" -gt "$notifications" ]]

    systemctl stop varlink-test-slow.service
    wait "$watcher_pid" 2>/dev/null || true
    watcher_pid=
}

testcase_reexec_while_streaming() {
    trap at_exit EXIT

    # The service manager passes the varlink connection across reexecution, hence the streaming client
    # must still get the final reply afterwards, and the status update sent after the reexecution must
    # arrive as a plain unit notification (the final reply carries runtime too, so it can't prove that).
    cat >/run/systemd/system/varlink-test-reexec.service <<UNIT
[Service]
Type=notify
NotifyAccess=all
RemainAfterExit=yes
ExecStart=/bin/sh -ec 'systemctl daemon-reexec; systemd-notify --status=after-reexec; sleep 1; systemd-notify --ready'
UNIT
    systemctl daemon-reload

    result=$(timeout 60 varlinkctl call --more /run/systemd/io.systemd.Manager io.systemd.Unit.EnqueueJob \
        '{"names": ["varlink-test-reexec.service"], "jobType": "start", "notifyJobChanges": true, "notifyUnitChanges": true}')
    printf '%s' "$result" | jq --seq --slurp -e 'any(.[]; .job.Result == "done")' >/dev/null
    printf '%s' "$result" | jq --seq --slurp -e 'any(.[]; .runtime.Service.StatusText == "after-reexec" and (has("job") | not))' >/dev/null
    systemctl is-active varlink-test-reexec.service

    # Reexecute and Reload reply once they are complete
    timeout 60 varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Manager.Reexecute '{}'
    timeout 60 varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Manager.Reload '{}'
    systemctl is-active varlink-test-reexec.service
}

slow_client_at_exit() {
    local pid

    systemctl stop varlink-transient-slow-client.service 2>/dev/null || true
    systemctl reset-failed varlink-transient-slow-client.service 2>/dev/null || true
    for pid in "${CHILD_PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
        # Resume stopped clients so the pending SIGTERM can take effect.
        kill -CONT "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    rm -f /run/varlink-slow-client.{output,errors,started,go,ready}
}

# Shell snippets expand their parameters in the child shell.
# shellcheck disable=SC2016
testcase_slow_notification_client() {
    CHILD_PIDS=()
    trap slow_client_at_exit EXIT

    local unit=varlink-transient-slow-client.service client_pid result

    rm -f /run/varlink-slow-client.*

    # Start a service that waits until the watching client is paused.
    systemd-run --quiet --unit="$unit" \
        -p Type=notify -p NotifyAccess=all -p TimeoutStartSec=660 \
        bash -ec '
            # Wait until the client is subscribed and stopped.
            touch /run/varlink-slow-client.started
            until [[ -e /run/varlink-slow-client.go ]]; do sleep 0.1; done

            # Fill the 16 MiB output buffer (JSON_STREAM_BUFFER_MAX_DEFAULT).
            # Each update waits for the manager to process it.
            status=$(printf "x%.0s" {1..4000})
            for ((i = 0; i < 6144; i++)); do
                systemd-notify --status="$i $status"
            done

            # Finish the start job and keep the service alive for the second client.
            systemd-notify --ready
            touch /run/varlink-slow-client.ready
            exec sleep infinity
        ' &
    CHILD_PIDS+=("$!")
    timeout 30 bash -c 'until [[ -e /run/varlink-slow-client.started ]]; do sleep 0.1; done'

    # Subscribe and wait for the first reply to confirm the watch is installed.
    varlinkctl call --more --json=short --timeout=infinity --graceful=io.systemd.Disconnected --graceful=io.systemd.System \
        /run/systemd/io.systemd.Manager io.systemd.Unit.EnqueueJob \
        '{"names":["'"$unit"'"],"jobType":"start","notifyJobChanges":true,"notifyUnitChanges":true}' \
        >/run/varlink-slow-client.output 2>/run/varlink-slow-client.errors &
    client_pid=$!
    CHILD_PIDS+=("$client_pid")
    timeout 10 bash -c 'until [[ "$(jq --seq --slurp -r ".[0].job.State" /run/varlink-slow-client.output 2>/dev/null)" == running ]]; do sleep 0.1; done'

    # Stop the client before allowing the service to generate updates.
    kill -STOP "$client_pid"
    timeout 10 bash -c 'until grep -q "^State:.*T" "/proc/$1/status"; do sleep 0.1; done' bash "$client_pid"

    # Let the service fill the output buffer and complete its startup job.
    touch /run/varlink-slow-client.go
    timeout 600 bash -c 'until [[ -e /run/varlink-slow-client.ready ]]; do sleep 0.1; done'
    assert_unit_state "$unit" active running

    # The final reply cannot fit. The client must receive an error or observe a disconnect.
    kill -CONT "$client_pid"
    timeout 30 tail --pid="$client_pid" -f /dev/null
    wait "$client_pid"
    grep -F 'Method call returned expected error: io.systemd.Disconnected' /run/varlink-slow-client.errors ||
        grep -F 'ENOBUFS' /run/varlink-slow-client.output

    # The old unit subscription must be released so a new connection can watch it.
    result=$(varlinkctl call --more /run/systemd/io.systemd.Manager io.systemd.Unit.EnqueueJob \
        '{"names":["'"$unit"'"],"jobType":"start","notifyUnitChanges":true}')
    assert_eq "$(jq --seq -r '.job.Result // empty' <<<"$result")" "done"
}

run_testcases
