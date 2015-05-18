#!/bin/bash -x

# Test merging of a --job-mode=ignore-dependencies job into a previously
# installed job.

systemctl start --no-block hello-after-sleep.target
# sleep is now running, hello/start is waiting. Verify that:
systemctl list-jobs > /root/list-jobs.txt
grep 'sleep\.service.*running' /root/list-jobs.txt || exit 1
grep 'hello\.service.*waiting' /root/list-jobs.txt || exit 1

# This is supposed to finish quickly, not wait for sleep to finish.
START_SEC=$(date -u '+%s')
systemctl start --job-mode=ignore-dependencies hello
END_SEC=$(date -u '+%s')
ELAPSED=$(($END_SEC-$START_SEC))

[ "$ELAPSED" -lt 3 ] || exit 1

# sleep should still be running, hello not.
systemctl list-jobs > /root/list-jobs.txt
grep 'sleep\.service.*running' /root/list-jobs.txt || exit 1
grep 'hello\.service' /root/list-jobs.txt && exit 1
systemctl stop sleep.service hello-after-sleep.target || exit 1

# Test for a crash when enqueueing a JOB_NOP when other job already exists
systemctl start --no-block hello-after-sleep.target || exit 1
# hello.service should still be waiting, so these try-restarts will collapse
# into NOPs.
systemctl try-restart --job-mode=fail hello.service || exit 1
systemctl try-restart hello.service || exit 1
systemctl stop hello.service sleep.service hello-after-sleep.target || exit 1

# TODO: add more job queueing/merging tests here.

# Test for irreversible jobs
systemctl start unstoppable.service || exit 1

# This is expected to fail with 'job cancelled'
systemctl stop unstoppable.service && exit 1
# But this should succeed
systemctl stop --job-mode=replace-irreversibly unstoppable.service || exit 1

# We're going to shutdown soon. Let's see if it succeeds when
# there's an active service that tries to be unstoppable.
# Shutdown of the container/VM will hang if not.
systemctl start unstoppable.service || exit 1

touch /testok
exit 0
