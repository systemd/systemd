#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Test changing the main PID

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# The main service PID should be the parent bash process
MAINPID="${PPID:?}"
test "$(systemctl show -P MainPID TEST-07-PID1.service)" -eq "$MAINPID"

# Start a test process inside of our own cgroup
sleep infinity &
INTERNALPID=$!
disown

# Start a test process outside of our own cgroup
systemd-run -p DynamicUser=1 --unit=test-sleep.service sleep infinity
EXTERNALPID="$(systemctl show -P MainPID test-sleep.service)"

# Update our own main PID to the external test PID, this should work
systemd-notify MAINPID="$EXTERNALPID"
test "$(systemctl show -P MainPID TEST-07-PID1.service)" -eq "$EXTERNALPID"

# Update our own main PID to the internal test PID, this should work, too
systemd-notify MAINPID=$INTERNALPID
test "$(systemctl show -P MainPID TEST-07-PID1.service)" -eq "$INTERNALPID"

# Update it back to our own PID, this should also work
systemd-notify MAINPID="$MAINPID"
test "$(systemctl show -P MainPID TEST-07-PID1.service)" -eq "$MAINPID"

# Try to set it to PID 1, which it should ignore, because that's the manager
systemd-notify MAINPID=1
test "$(systemctl show -P MainPID TEST-07-PID1.service)" -eq "$MAINPID"

# Try to set it to PID 0, which is invalid and should be ignored
systemd-notify MAINPID=0
test "$(systemctl show -P MainPID TEST-07-PID1.service)" -eq "$MAINPID"

# Try to set it to a valid but non-existing PID, which should be ignored. (Note
# that we set the PID to a value well above any known /proc/sys/kernel/pid_max,
# which means we can be pretty sure it doesn't exist by coincidence)
systemd-notify MAINPID=1073741824
test "$(systemctl show -P MainPID TEST-07-PID1.service)" -eq "$MAINPID"

# Change it again to the external PID, without privileges this time. This should be ignored, because the PID is from outside of our cgroup and we lack privileges.
systemd-notify --uid=1000 MAINPID="$EXTERNALPID"
test "$(systemctl show -P MainPID TEST-07-PID1.service)" -eq "$MAINPID"

# Change it again to the internal PID, without privileges this time. This should work, as the process is on our cgroup, and that's enough even if we lack privileges.
systemd-notify --uid=1000 MAINPID="$INTERNALPID"
test "$(systemctl show -P MainPID TEST-07-PID1.service)" -eq "$INTERNALPID"

# Update it back to our own PID, this should also work
systemd-notify --uid=1000 MAINPID="$MAINPID"
test "$(systemctl show -P MainPID TEST-07-PID1.service)" -eq "$MAINPID"

cat >/tmp/test-mainpid.sh <<\EOF
#!/usr/bin/env bash

set -eux
set -o pipefail

# Create a number of children, and make one the main one
sleep infinity &
disown

sleep infinity &
MAINPID=$!
disown

sleep infinity &
disown

echo $MAINPID >/run/mainpidsh/pid
EOF
chmod +x /tmp/test-mainpid.sh

systemd-run --unit=test-mainpidsh.service \
            -p StandardOutput=tty \
            -p StandardError=tty \
            -p Type=forking \
            -p RuntimeDirectory=mainpidsh \
            -p PIDFile=/run/mainpidsh/pid \
            /tmp/test-mainpid.sh
test "$(systemctl show -P MainPID test-mainpidsh.service)" -eq "$(cat /run/mainpidsh/pid)"

cat >/tmp/test-mainpid2.sh <<\EOF
#!/usr/bin/env bash

set -eux
set -o pipefail

# Create a number of children, and make one the main one
sleep infinity &
disown

sleep infinity &
MAINPID=$!
disown

sleep infinity &
disown

echo $MAINPID >/run/mainpidsh2/pid
chown 1001:1001 /run/mainpidsh2/pid
EOF
chmod +x /tmp/test-mainpid2.sh

systemd-run --unit=test-mainpidsh2.service \
            -p StandardOutput=tty \
            -p StandardError=tty \
            -p Type=forking \
            -p RuntimeDirectory=mainpidsh2 \
            -p PIDFile=/run/mainpidsh2/pid \
            /tmp/test-mainpid2.sh
test "$(systemctl show -P MainPID test-mainpidsh2.service)" -eq "$(cat /run/mainpidsh2/pid)"

cat >/dev/shm/test-mainpid3.sh <<EOF
#!/usr/bin/env bash

set -eux
set -o pipefail

sleep infinity &
disown

sleep infinity &
disown

sleep infinity &
disown

# Let's try to play games, and link up a privileged PID file
ln -s ../mainpidsh/pid /run/mainpidsh3/pid

# Quick assertion that the link isn't dead
test -f /run/mainpidsh3/pid
EOF
chmod 755 /dev/shm/test-mainpid3.sh

# This has to fail, as we shouldn't accept the dangerous PID file, and then
# inotify-wait on it to be corrected which we never do.
(! systemd-run \
    --unit=test-mainpidsh3.service \
    -p StandardOutput=tty \
    -p StandardError=tty \
    -p Type=forking \
    -p RuntimeDirectory=mainpidsh3 \
    -p PIDFile=/run/mainpidsh3/pid \
    -p DynamicUser=1 \
    `# Make sanitizers happy when DynamicUser=1 pulls in instrumented systemd NSS modules` \
    -p EnvironmentFile=-/usr/lib/systemd/systemd-asan-env \
    -p TimeoutStartSec=2s \
    /dev/shm/test-mainpid3.sh)

# Test that this failed due to timeout, and not some other error
test "$(systemctl show -P Result test-mainpidsh3.service)" = timeout

# Test that scope units work
systemd-run --scope --unit test-true.scope true
test "$(systemctl show -P Result test-true.scope)" = success

# Test that user scope units work as well

systemctl start user@4711.service
runas testuser systemd-run --scope --user --unit test-true.scope true
test "$(systemctl show -P Result test-true.scope)" = success
