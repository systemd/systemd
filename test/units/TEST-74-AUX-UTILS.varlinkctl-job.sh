#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# test io.systemd.Job
varlinkctl introspect /run/systemd/io.systemd.Manager io.systemd.Job

# List with no jobs pending — should return empty with --more
varlinkctl --more call /run/systemd/io.systemd.Manager io.systemd.Job.List '{}' --graceful=io.systemd.Job.NoSuchJob

# Without --more and no filter, must fail (streaming required)
(! varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Job.List '{}')

# Error cases: non-existent job ID, non-existent unit
(! varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Job.List '{"id": 999999}')
(! varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Job.List '{"unit": "non-existent.service"}')

# Invalid inputs
(! varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Job.List '{"id": 0}')
(! varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Job.List '{"unit": ""}')

SUBSCRIBE_PIDS=()
SUBSCRIBE_FILES=()

at_exit() {
    if [[ ${#SUBSCRIBE_PIDS[@]} -gt 0 ]]; then
        kill "${SUBSCRIBE_PIDS[@]}" 2>/dev/null || true
        wait "${SUBSCRIBE_PIDS[@]}" 2>/dev/null || true
    fi
    if [[ ${#SUBSCRIBE_FILES[@]} -gt 0 ]]; then
        rm -f "${SUBSCRIBE_FILES[@]}"
    fi
    systemctl stop varlink-test-job.service varlink-test-subscribe-restart.service 2>/dev/null || true
    rm -f /run/systemd/system/varlink-test-job.service
    systemctl daemon-reload
}
trap at_exit EXIT

# Create a job by starting a slow service, then test List/Cancel
cat >/run/systemd/system/varlink-test-job.service <<UNIT
[Service]
Type=notify
ExecStart=sleep infinity
UNIT
systemctl daemon-reload

# Start asynchronously to create a job
systemctl start --no-block varlink-test-job.service

# The job should now be visible
job_id=$(varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Job.List '{"unit": "varlink-test-job.service"}' | jq -r '.Id')
test "$job_id" -gt 0

# Verify job fields
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Job.List '{"unit": "varlink-test-job.service"}' | jq -e '.Unit == "varlink-test-job.service"'
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Job.List '{"unit": "varlink-test-job.service"}' | jq -e '.JobType == "start"'
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Job.List '{"unit": "varlink-test-job.service"}' | jq -e '.State'

# Lookup by job ID should return the same job
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Job.List "{\"id\": $job_id}" | jq -e ".Unit == \"varlink-test-job.service\""

# Lookup by both id and unit (matching) should succeed
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Job.List "{\"id\": $job_id, \"unit\": \"varlink-test-job.service\"}" | jq -e ".Id == $job_id"

# Lookup by both id and unit (conflicting) should fail
(! varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Job.List "{\"id\": $((job_id + 1)), \"unit\": \"varlink-test-job.service\"}")

# The job should appear in the full listing
varlinkctl --more call /run/systemd/io.systemd.Manager io.systemd.Job.List '{}' | grep "varlink-test-job.service"

# Cancel the job
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Job.Cancel "{\"id\": $job_id}"

# The job should no longer exist
(! varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Job.List '{"unit": "varlink-test-job.service"}')

# Cancel with non-existent job ID should fail
(! varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Job.Cancel '{"id": 999999}')

# Test ClearAll: create another job, then clear all
systemctl start --no-block varlink-test-job.service
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Job.List '{"unit": "varlink-test-job.service"}' | jq -e '.Id'
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Job.ClearAll '{}'

# No jobs should remain for our test unit
(! varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Job.List '{"unit": "varlink-test-job.service"}')

# Test Subscribe. The method requires 'more'.
(! varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Job.Subscribe '{}')

# A filter entry must be a unit name or a glob pattern
(! varlinkctl --more call /run/systemd/io.systemd.Manager io.systemd.Job.Subscribe '{"units": ["not a unit name"]}')

# The filter takes a limited number of entries
(! varlinkctl --more call /run/systemd/io.systemd.Manager io.systemd.Job.Subscribe \
    "$(jq --null-input --compact-output '{units: [range(65) | "varlink-test-\(.).service"]}')")

# A subscription does not end by itself, hence run each one in the background. at_exit() ends them.
subscribe() {
    local output

    output="$(mktemp)"
    SUBSCRIBE_FILES+=("$output")
    varlinkctl --more call /run/systemd/io.systemd.Manager io.systemd.Job.Subscribe "$2" >"$output" &
    SUBSCRIBE_PIDS+=($!)
    printf -v "$1" '%s' "$output"
}

# The job of this unit stays queued: the service never sends READY=1
systemctl start --no-block varlink-test-job.service

subscribe SUBSCRIBE_ALL '{}'
subscribe SUBSCRIBE_GLOB '{"units": ["varlink-test-subscribe-*.service"]}'
subscribe SUBSCRIBE_NAME '{"units": ["varlink-test-other.service"]}'
subscribe SUBSCRIBE_QUEUED '{"units": ["varlink-test-job.service"]}'

subscription_has() {
    timeout 30 bash -c "until jq --seq --slurp -e '$2' '$1' >/dev/null 2>&1; do sleep 0.2; done"
}

job_done() {
    echo "any(.[]; .job.Unit == \"$1\" and .job.State == \"finished\" and .job.Result == \"done\")"
}

# The ready notification concludes the initial list: the subscription is in effect
subscription_has "$SUBSCRIBE_ALL" 'any(.[]; .ready == true)'
subscription_has "$SUBSCRIBE_GLOB" 'any(.[]; .ready == true)'
subscription_has "$SUBSCRIBE_NAME" 'any(.[]; .ready == true)'
subscription_has "$SUBSCRIBE_QUEUED" 'any(.[]; .ready == true)'

# The initial list reports the queued job before the ready notification
jq --seq --slurp -e '.[0].job.Unit == "varlink-test-job.service" and .[0].job.State != "finished" and .[1].ready == true' "$SUBSCRIBE_QUEUED"
systemctl stop varlink-test-job.service
subscription_has "$SUBSCRIBE_QUEUED" 'any(.[]; .job.Unit == "varlink-test-job.service" and .job.JobType == "start" and .job.Result == "canceled")'

# The last job of each run matches its filter: all notifications before it are in the output by then
systemd-run --wait --unit=varlink-test-subscribe-one.service true
systemd-run --wait --unit=varlink-test-other.service true
systemd-run --wait --unit=varlink-test-subscribe-two.service true
systemd-run --wait --unit=varlink-test-other.service true

# Without a filter, the subscription reports the jobs of all units
subscription_has "$SUBSCRIBE_ALL" "$(job_done varlink-test-subscribe-one.service)"
subscription_has "$SUBSCRIBE_ALL" "$(job_done varlink-test-subscribe-two.service)"
subscription_has "$SUBSCRIBE_ALL" "$(job_done varlink-test-other.service)"

# A job is reported from the moment it is enqueued
subscription_has "$SUBSCRIBE_ALL" 'any(.[]; .job.Unit == "varlink-test-subscribe-one.service" and .job.State == "waiting")'

# With a filter, the subscription reports the jobs of the matching units only
subscription_has "$SUBSCRIBE_GLOB" "$(job_done varlink-test-subscribe-one.service)"
subscription_has "$SUBSCRIBE_GLOB" "$(job_done varlink-test-subscribe-two.service)"
jq --seq --slurp -e 'all(.[]; .job == null or (.job.Unit | startswith("varlink-test-subscribe-")))' "$SUBSCRIBE_GLOB"
subscription_has "$SUBSCRIBE_NAME" '[.[] | select(.job.State == "finished")] | length == 2'
jq --seq --slurp -e 'all(.[]; .job == null or .job.Unit == "varlink-test-other.service")' "$SUBSCRIBE_NAME"

# The stop phase of a restart job finishes with a result, then the job continues as a start job. Only
# a finished job carries a result.
systemd-run --unit=varlink-test-subscribe-restart.service -p RemainAfterExit=yes true
systemctl restart varlink-test-subscribe-restart.service
subscription_has "$SUBSCRIBE_ALL" '[.[] | select(.job.Unit == "varlink-test-subscribe-restart.service" and .job.State == "finished")] | length == 2'
subscription_has "$SUBSCRIBE_GLOB" 'group_by(.job.Id) | any(.[]; any(.[]; .job.JobType == "restart") and any(.[]; .job.JobType == "start"))'
jq --seq --slurp -e 'all(.[]; .job == null or ((.job.State == "finished") == (.job.Result != null)))' "$SUBSCRIBE_ALL"
