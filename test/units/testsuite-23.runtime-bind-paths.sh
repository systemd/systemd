#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

# Test adding new BindPaths while unit is already running

at_exit() {
    set +e

    rm -f /run/testsuite-23-marker-{fixed,runtime}
    rm -fr /run/inaccessible
}

trap at_exit EXIT

echo "MARKER_FIXED" >/run/testsuite-23-marker-fixed
mkdir /run/inaccessible

systemctl start testsuite-23-namespaced.service

# Ensure that inaccessible paths aren't bypassed by the runtime setup,
(! systemctl bind --mkdir testsuite-23-namespaced.service /run/testsuite-23-marker-fixed /run/inaccessible/testfile-marker-fixed)

echo "MARKER_WRONG" >/run/testsuite-23-marker-wrong
echo "MARKER_RUNTIME" >/run/testsuite-23-marker-runtime

# Mount twice to exercise mount-beneath (on kernel 6.5+, on older kernels it will just overmount)
systemctl bind --mkdir testsuite-23-namespaced.service /run/testsuite-23-marker-wrong /tmp/testfile-marker-runtime
test "$(systemctl show -P SubState testsuite-23-namespaced.service)" = "running"
systemctl bind --mkdir testsuite-23-namespaced.service /run/testsuite-23-marker-runtime /tmp/testfile-marker-runtime

timeout 10 bash -xec 'while [[ "$(systemctl show -P SubState testsuite-23-namespaced.service)" == running ]]; do sleep .5; done'
systemctl is-active testsuite-23-namespaced.service

# Now test that systemctl bind fails when attempted on a non-namespaced unit
systemctl start testsuite-23-non-namespaced.service

(! systemctl bind --mkdir testsuite-49-non-namespaced.service /run/testsuite-23-marker-runtime /tmp/testfile-marker-runtime)

timeout 10 bash -xec 'while [[ "$(systemctl show -P SubState testsuite-23-non-namespaced.service)" == running ]]; do sleep .5; done'
(! systemctl is-active testsuite-23-non-namespaced.service)
