#!/usr/bin/env bash
set -ex

echo "MARKER_FIXED" > /run/testservice-57-fixed
mkdir -p /run/inaccessible

systemctl start testsuite-57-namespaced.service

# Ensure that inaccessible paths aren't bypassed by the runtime setup
set +e
systemctl bind --mkdir testsuite-57-namespaced.service /run/testservice-57-fixed /run/inaccessible/testfile_fixed && exit 1
set -e

echo "MARKER_RUNTIME" > /run/testservice-57-runtime

systemctl bind --mkdir testsuite-57-namespaced.service /run/testservice-57-runtime /tmp/testfile_runtime

while systemctl show -P SubState testsuite-57-namespaced.service | grep -q running
do
    sleep 0.1
done

systemctl is-active testsuite-57-namespaced.service

# Now test that systemctl bind fails when attempted on a non-namespaced unit
systemctl start testsuite-57-non-namespaced.service

set +e
systemctl bind --mkdir testsuite-57-non-namespaced.service /run/testservice-57-runtime /tmp/testfile_runtime && exit 1
set -e

while systemctl show -P SubState testsuite-57-non-namespaced.service | grep -q running
do
    sleep 0.1
done

set +e
systemctl is-active testsuite-57-non-namespaced.service && exit 1
set -e

echo OK > /testok

exit 0
