#!/bin/bash -ex

# Test merging of a --job-mode=ignore-dependencies job into a previously
# installed job.

systemctl start --no-block hello-after-sleep.target

systemctl list-jobs > /root/list-jobs.txt
while ! grep 'sleep\.service.*running' /root/list-jobs.txt; do
    systemctl list-jobs > /root/list-jobs.txt
done

grep 'hello\.service.*waiting' /root/list-jobs.txt

# This is supposed to finish quickly, not wait for sleep to finish.
START_SEC=$(date -u '+%s')
systemctl start --job-mode=ignore-dependencies hello
END_SEC=$(date -u '+%s')
ELAPSED=$(($END_SEC-$START_SEC))

[ "$ELAPSED" -lt 3 ]

# sleep should still be running, hello not.
systemctl list-jobs > /root/list-jobs.txt
grep 'sleep\.service.*running' /root/list-jobs.txt
grep 'hello\.service' /root/list-jobs.txt && exit 1
systemctl stop sleep.service hello-after-sleep.target

# Some basic testing that --show-transaction does something useful
! systemctl is-active systemd-importd
systemctl -T start systemd-importd
systemctl is-active systemd-importd
systemctl --show-transaction stop systemd-importd
! systemctl is-active systemd-importd

# Test for a crash when enqueuing a JOB_NOP when other job already exists
systemctl start --no-block hello-after-sleep.target
# hello.service should still be waiting, so these try-restarts will collapse
# into NOPs.
systemctl try-restart --job-mode=fail hello.service
systemctl try-restart hello.service
systemctl stop hello.service sleep.service hello-after-sleep.target

# TODO: add more job queueing/merging tests here.

# Test for irreversible jobs
systemctl start unstoppable.service

# This is expected to fail with 'job cancelled'
systemctl stop unstoppable.service && exit 1
# But this should succeed
systemctl stop --job-mode=replace-irreversibly unstoppable.service

# We're going to shutdown soon. Let's see if it succeeds when
# there's an active service that tries to be unstoppable.
# Shutdown of the container/VM will hang if not.
systemctl start unstoppable.service

# Test waiting for a started unit(s) to terminate again
cat <<EOF >  /run/systemd/system/wait2.service
[Unit]
Description=Wait for 2 seconds
[Service]
ExecStart=/bin/sh -ec 'sleep 2'
EOF
cat <<EOF >  /run/systemd/system/wait5fail.service
[Unit]
Description=Wait for 5 seconds and fail
[Service]
ExecStart=/bin/sh -ec 'sleep 5; false'
EOF

# wait2 succeeds
START_SEC=$(date -u '+%s')
systemctl start --wait wait2.service
END_SEC=$(date -u '+%s')
ELAPSED=$(($END_SEC-$START_SEC))
[[ "$ELAPSED" -ge 2 ]] && [[ "$ELAPSED" -le 4 ]] || exit 1

# wait5fail fails, so systemctl should fail
START_SEC=$(date -u '+%s')
! systemctl start --wait wait2.service wait5fail.service || exit 1
END_SEC=$(date -u '+%s')
ELAPSED=$(($END_SEC-$START_SEC))
[[ "$ELAPSED" -ge 5 ]] && [[ "$ELAPSED" -le 7 ]] || exit 1

touch /testok
