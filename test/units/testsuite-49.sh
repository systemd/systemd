#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux

echo "MARKER_FIXED" >/run/testservice-49-fixed
mkdir -p /run/inaccessible

systemctl start testsuite-49-namespaced.service

# Ensure that inaccessible paths aren't bypassed by the runtime setup
set +e
systemctl bind --mkdir testsuite-49-namespaced.service /run/testservice-49-fixed /run/inaccessible/testfile_fixed && exit 1
set -e

echo "MARKER_RUNTIME" >/run/testservice-49-runtime

systemctl bind --mkdir testsuite-49-namespaced.service /run/testservice-49-runtime /tmp/testfile_runtime

while systemctl show -P SubState testsuite-49-namespaced.service | grep -q running
do
    sleep 0.1
done

systemctl is-active testsuite-49-namespaced.service

# Now test that systemctl bind fails when attempted on a non-namespaced unit
systemctl start testsuite-49-non-namespaced.service

set +e
systemctl bind --mkdir testsuite-49-non-namespaced.service /run/testservice-49-runtime /tmp/testfile_runtime && exit 1
set -e

while systemctl show -P SubState testsuite-49-non-namespaced.service | grep -q running
do
    sleep 0.1
done

set +e
systemctl is-active testsuite-49-non-namespaced.service && exit 1
set -e

echo OK >/testok

exit 0
