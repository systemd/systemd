#!/bin/bash
set -ex
set -o pipefail

systemd-analyze log-level debug
systemd-analyze log-target console

test `systemctl show -p MainPID --value testsuite.service` -eq $$

# Start a test process inside of our own cgroup
sleep infinity &
INTERNALPID=$!
disown

# Start a test process outside of our own cgroup
systemd-run -p DynamicUser=1 --unit=sleep.service /bin/sleep infinity
EXTERNALPID=`systemctl show -p MainPID --value sleep.service`

# Update our own main PID to the external test PID, this should work
systemd-notify MAINPID=$EXTERNALPID
test `systemctl show -p MainPID --value testsuite.service` -eq $EXTERNALPID

# Update our own main PID to the internal test PID, this should work, too
systemd-notify MAINPID=$INTERNALPID
test `systemctl show -p MainPID --value testsuite.service` -eq $INTERNALPID

# Update it back to our own PID, this should also work
systemd-notify MAINPID=$$
test `systemctl show -p MainPID --value testsuite.service` -eq $$

# Try to set it to PID 1, which it should ignore, because that's the manager
systemd-notify MAINPID=1
test `systemctl show -p MainPID --value testsuite.service` -eq $$

# Try to set it to PID 0, which is invalid and should be ignored
systemd-notify MAINPID=0
test `systemctl show -p MainPID --value testsuite.service` -eq $$

# Try to set it to a valid but non-existing PID, which should be ignored. (Note
# that we set the PID to a value well above any known /proc/sys/kernel/pid_max,
# which means we can be pretty sure it doesn't exist by coincidence)
systemd-notify MAINPID=1073741824
test `systemctl show -p MainPID --value testsuite.service` -eq $$

# Change it again to the external PID, without privileges this time. This should be ignored, because the PID is from outside of our cgroup and we lack privileges.
systemd-notify --uid=1000 MAINPID=$EXTERNALPID
test `systemctl show -p MainPID --value testsuite.service` -eq $$

# Change it again to the internal PID, without privileges this time. This should work, as the process is on our cgroup, and that's enough even if we lack privileges.
systemd-notify --uid=1000 MAINPID=$INTERNALPID
test `systemctl show -p MainPID --value testsuite.service` -eq $INTERNALPID

# Update it back to our own PID, this should also work
systemd-notify --uid=1000 MAINPID=$$
test `systemctl show -p MainPID --value testsuite.service` -eq $$

cat >/tmp/mainpid.sh <<EOF
#!/bin/bash

set -eux
set -o pipefail

# Create a number of children, and make one the main one
sleep infinity &
disown

sleep infinity &
MAINPID=\$!
disown

sleep infinity &
disown

echo \$MAINPID > /run/mainpidsh/pid
EOF
chmod +x /tmp/mainpid.sh

systemd-run --unit=mainpidsh.service -p StandardOutput=tty -p StandardError=tty -p Type=forking -p RuntimeDirectory=mainpidsh -p PIDFile=/run/mainpidsh/pid /tmp/mainpid.sh
test `systemctl show -p MainPID --value mainpidsh.service` -eq `cat /run/mainpidsh/pid`

cat >/tmp/mainpid2.sh <<EOF
#!/bin/bash

set -eux
set -o pipefail

# Create a number of children, and make one the main one
sleep infinity &
disown

sleep infinity &
MAINPID=\$!
disown

sleep infinity &
disown

echo \$MAINPID > /run/mainpidsh2/pid
chown 1001:1001 /run/mainpidsh2/pid
EOF
chmod +x /tmp/mainpid2.sh

systemd-run --unit=mainpidsh2.service -p StandardOutput=tty -p StandardError=tty -p Type=forking -p RuntimeDirectory=mainpidsh2 -p PIDFile=/run/mainpidsh2/pid /tmp/mainpid2.sh
test `systemctl show -p MainPID --value mainpidsh2.service` -eq `cat /run/mainpidsh2/pid`

cat >/dev/shm/mainpid3.sh <<EOF
#!/bin/bash

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
chmod 755 /dev/shm/mainpid3.sh

# This has to fail, as we shouldn't accept the dangerous PID file, and then inotify-wait on it to be corrected which we never do
! systemd-run --unit=mainpidsh3.service -p StandardOutput=tty -p StandardError=tty -p Type=forking -p RuntimeDirectory=mainpidsh3 -p PIDFile=/run/mainpidsh3/pid -p DynamicUser=1 -p TimeoutStartSec=2s /dev/shm/mainpid3.sh

# Test that this failed due to timeout, and not some other error
test `systemctl show -p Result --value mainpidsh3.service` = timeout

systemd-analyze log-level info

echo OK > /testok

exit 0
