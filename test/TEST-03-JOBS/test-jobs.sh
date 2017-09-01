#!/bin/bash -xe

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

cat <<EOF >  /run/systemd/system/oneshot-wait2.service
[Unit]
Description=Wait for 2 seconds
[Service]
Type=oneshot
ExecStart=/bin/sh -ec 'sleep 2'
EOF

# Restart jobs do not change their type to "start"
systemctl restart --no-block oneshot-wait2.service
sleep 1
LC_ALL=C systemctl list-jobs > /root/list-jobs.txt
grep "oneshot-wait2.service.* [ ]*restart [ ]*running$" /root/list-jobs.txt || exit 1

# Test different types of service failure
cat <<EOF >  /run/systemd/system/fail-start.service
[Unit]
Description=Fail to start
[Service]
Type=oneshot
ExecStart=/bin/sh -c false
EOF

! WARN="$(systemctl start fail-start.service 2>&1)" || exit 1
[ "$WARN" != "" ] || exit 1
systemctl is-failed fail-start.service || exit 1

systemctl reset-failed fail-start.service || exit 1
! systemctl is-failed fail-start.service || exit 1

cat <<EOF >  /run/systemd/system/fail-reload.service
[Unit]
Description=Fail to reload
[Service]
Type=oneshot
RemainAfterExit=true
ExecStart=/bin/sh -c true
ExecReload=/bin/sh -c false
EOF

systemctl start fail-reload.service || exit 1

! WARN="$(systemctl reload fail-reload.service 2>&1)" || exit 1
[ "$WARN" != "" ] || exit 1

# reload failure doesn't fail the service
! systemctl is-failed fail-reload.service || exit 1

cat <<EOF >  /run/systemd/system/fail-stop.service
[Unit]
Description=Fail to stop
[Service]
Type=oneshot
RemainAfterExit=true
ExecStart=/bin/sh -c true
ExecStop=/bin/sh -c false
EOF

systemctl start fail-stop.service || exit 1

# When stop jobs have to resort to SIGKILL, they are not considered to fail.
# However `systemctl` will warn...
WARN="$(systemctl stop fail-stop.service 2>&1)" || exit 1
[ "$WARN" != "" ] || exit 1

# ... and the service is marked as failed.
systemctl is-failed fail-stop.service || exit 1

# A sucessful start clears the failed state
systemctl start fail-stop.service || exit 1
! systemctl is-failed fail-stop.service || exit 1

# restart = stop+start.  We should get the same warning from the stop...
WARN="$(systemctl restart fail-stop.service 2>&1)" || exit 1
[ "$WARN" != "" ] || exit 1

# ... but the failed state is cleared by the successful start
! systemctl is-failed fail-stop.service || exit 1

touch /testok
