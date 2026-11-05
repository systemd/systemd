#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh

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

    varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.EnqueueJob '{"names": ["varlink-test-enqueue.service"], "jobType": "stop"}' | jq -e '.job.JobType == "stop"'
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

run_testcases
