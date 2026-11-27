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

at_exit() {
    systemctl stop varlink-test-job.service 2>/dev/null || true
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

SUBSCRIBE_ALL="$(mktemp)"
SUBSCRIBE_GLOB="$(mktemp)"
SUBSCRIBE_NAME="$(mktemp)"

# A subscription does not end by itself, hence run each one in the background
varlinkctl --more call /run/systemd/io.systemd.Manager io.systemd.Job.Subscribe '{}' >"$SUBSCRIBE_ALL" &
SUBSCRIBE_ALL_PID=$!
varlinkctl --more call /run/systemd/io.systemd.Manager io.systemd.Job.Subscribe '{"units": ["varlink-test-subscribe-*.service"]}' >"$SUBSCRIBE_GLOB" &
SUBSCRIBE_GLOB_PID=$!
varlinkctl --more call /run/systemd/io.systemd.Manager io.systemd.Job.Subscribe '{"units": ["varlink-test-other.service"]}' >"$SUBSCRIBE_NAME" &
SUBSCRIBE_NAME_PID=$!

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

kill "$SUBSCRIBE_ALL_PID" "$SUBSCRIBE_GLOB_PID" "$SUBSCRIBE_NAME_PID"
wait "$SUBSCRIBE_ALL_PID" "$SUBSCRIBE_GLOB_PID" "$SUBSCRIBE_NAME_PID" || true
rm -f "$SUBSCRIBE_ALL" "$SUBSCRIBE_GLOB" "$SUBSCRIBE_NAME"
