#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Test OnSuccess=/OnFailure= in combination

systemd-analyze log-level debug

# Start-up should fail, but the automatic restart should fix it
(! systemctl start success-failure-test )

# Wait until the first invocation finished & failed
while test ! -f /tmp/success-failure-test-ran ; do
    sleep .5
done

# Wait until the second invocation finished & succeeded
while test ! -f /tmp/success-failure-test-ran2 ; do
    sleep .5
done

# Verify it is indeed running
systemctl is-active -q success-failure-test

# The above should have caused the failure service to start (asynchronously)
while test "$(systemctl is-active success-failure-test-failure)" != "active" ; do
    sleep .5
done

# But the success service should not have started
test "$(systemctl is-active success-failure-test-success)" = "inactive"

systemctl stop success-failure-test-failure

# Do a clean kill of the service now
systemctl kill success-failure-test

# This should result in the success service to start
while test "$(systemctl is-active success-failure-test-success)" != "active" ; do
    sleep .5
done

# But the failure service should not have started again
test "$(systemctl is-active success-failure-test-failure)" = "inactive"

systemctl stop success-failure-test success-failure-test-success

systemd-analyze log-level info
