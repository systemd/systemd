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
