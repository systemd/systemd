#!/usr/bin/env bash
set -ex

echo "MARKER_FIXED" > /run/testservice-54-fixed
mkdir -p /run/inaccessible

# Adding a new mounts at runtime works if the unit is in the active state,
# so use Type=notify to make sure there's no race condition in the test
cat > /run/systemd/system/testservice-54a.service <<EOF
[Service]
RuntimeMaxSec=300
Type=notify
RemainAfterExit=yes
MountAPIVFS=yes
PrivateTmp=yes
BindPaths=/run/testservice-54-fixed:/tmp/testfile_fixed
InaccessiblePaths=/run/inaccessible
ExecStartPre=grep -q -F MARKER_FIXED /tmp/testfile_fixed
ExecStart=/bin/sh -c 'systemd-notify --ready; while ! grep -q -F MARKER_RUNTIME /tmp/testfile_runtime; do sleep 0.1; done; test ! -f /run/inaccessible/testfile_fixed'
EOF
systemctl start testservice-54a.service

# Ensure that inaccessible paths aren't bypassed by the runtime setup
set +e
systemctl set-property --runtime testservice-54a.service BindPaths=/run/testservice-54-fixed:/run/inaccessible/testfile_fixed && exit 1
set -e

echo "MARKER_RUNTIME" > /run/testservice-54-runtime

systemctl set-property --runtime testservice-54a.service BindPaths=/run/testservice-54-runtime:/tmp/testfile_runtime

while systemctl show -P SubState testservice-54a.service | grep -q running
do
    sleep 0.1
done

systemctl is-active testservice-54a.service

# Now restart and ensure the mount is still there
systemctl restart testservice-54a.service

while systemctl show -P SubState testservice-54a.service | grep -q running
do
    sleep 0.1
done

systemctl is-active testservice-54a.service

# Now test that set-property fails when attempted on a non-namespaced unit
cat > /run/systemd/system/testservice-54b.service <<EOF
[Service]
RuntimeMaxSec=10
Type=notify
RemainAfterExit=yes
ExecStart=/bin/sh -c 'systemd-notify --ready; while ! grep -q -F MARKER_RUNTIME /tmp/testfile_runtime; do sleep 0.1; done; exit 0'
EOF
systemctl start testservice-54b.service

set +e
systemctl set-property --runtime testservice-54b.service BindPaths=/run/testservice-54-runtime:/tmp/testfile_runtime && exit 1
set -e

while systemctl show -P SubState testservice-54b.service | grep -q running
do
    sleep 0.1
done

set +e
systemctl is-active testservice-54b.service && exit 1
set -e

echo OK > /testok

exit 0
