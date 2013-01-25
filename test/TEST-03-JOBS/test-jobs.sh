#!/bin/bash -x

# Test merging of a --ignore-dependencies job into a previously
# installed job.

systemctl start --no-block hello-after-sleep.target
# sleep is now running, hello/start is waiting. Verify that:
systemctl list-jobs > /root/list-jobs.txt
grep 'sleep\.service.*running' /root/list-jobs.txt || exit 1
grep 'hello\.service.*waiting' /root/list-jobs.txt || exit 1

# This is supposed to finish quickly, not wait for sleep to finish.
START_SEC=$(date -u '+%s')
systemctl start --ignore-dependencies hello
END_SEC=$(date -u '+%s')
ELAPSED=$(($END_SEC-$START_SEC))

[ "$ELAPSED" -lt 3 ] || exit 1

# sleep should still be running, hello not.
systemctl list-jobs > /root/list-jobs.txt
grep 'sleep\.service.*running' /root/list-jobs.txt || exit 1
grep 'hello\.service' /root/list-jobs.txt && exit 1

# TODO: add more job queueing/merging tests here.

touch /testok
exit 0
