#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

# Test adding new BindPaths while unit is already running

at_exit() {
    set +e

    rm -f /run/TEST-23-UNIT-FILE-marker-{fixed,runtime}
    rm -fr /run/inaccessible
}

trap at_exit EXIT

echo "MARKER_FIXED" >/run/TEST-23-UNIT-FILE-marker-fixed
mkdir /run/inaccessible

systemctl start TEST-23-UNIT-FILE-namespaced.service

# Ensure that inaccessible paths aren't bypassed by the runtime setup,
(! systemctl bind --mkdir TEST-23-UNIT-FILE-namespaced.service /run/TEST-23-UNIT-FILE-marker-fixed /run/inaccessible/testfile-marker-fixed)

echo "MARKER_WRONG" >/run/TEST-23-UNIT-FILE-marker-wrong
echo "MARKER_RUNTIME" >/run/TEST-23-UNIT-FILE-marker-runtime

# Mount twice to exercise mount-beneath (on kernel 6.5+, on older kernels it will just overmount)
systemctl bind --mkdir TEST-23-UNIT-FILE-namespaced.service /run/TEST-23-UNIT-FILE-marker-wrong /tmp/testfile-marker-runtime
test "$(systemctl show -P SubState TEST-23-UNIT-FILE-namespaced.service)" = "running"
systemctl bind --mkdir TEST-23-UNIT-FILE-namespaced.service /run/TEST-23-UNIT-FILE-marker-runtime /tmp/testfile-marker-runtime

timeout 10 bash -xec 'while [[ "$(systemctl show -P SubState TEST-23-UNIT-FILE-namespaced.service)" == running ]]; do sleep .5; done'
systemctl is-active TEST-23-UNIT-FILE-namespaced.service

test "$(busctl --json=short get-property org.freedesktop.systemd1 /org/freedesktop/systemd1/unit/TEST_2d23_2dUNIT_2dFILE_2dnamespaced_2eservice org.freedesktop.systemd1.Unit CanLiveMount)" = "{\"type\":\"b\",\"data\":true}"

# Now test that systemctl bind fails when attempted on a non-namespaced unit
systemctl start TEST-23-UNIT-FILE-non-namespaced.service

(! systemctl bind --mkdir TEST-23-UNIT-FILE-non-namespaced.service /run/TEST-23-UNIT-FILE-marker-runtime /tmp/testfile-marker-runtime)

test "$(busctl --json=short get-property org.freedesktop.systemd1 /org/freedesktop/systemd1/unit/TEST_2d23_2dUNIT_2dFILE_2dnon_2dnamespaced_2eservice org.freedesktop.systemd1.Unit CanLiveMount)" = "{\"type\":\"b\",\"data\":false}"

timeout 10 bash -xec 'while [[ "$(systemctl show -P SubState TEST-23-UNIT-FILE-non-namespaced.service)" == running ]]; do sleep .5; done'
(! systemctl is-active TEST-23-UNIT-FILE-non-namespaced.service)
