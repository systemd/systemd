#!/usr/bin/env bash
set -eux
set -o pipefail

systemd-analyze log-level debug
systemd-analyze log-target journal

NUM_DIRS=20

# mount/unmount enough times to trigger the /proc/self/mountinfo parsing rate limiting

for ((i = 0; i < NUM_DIRS; i++)); do
    mkdir "/tmp/meow$i"
done

for ((i = 0; i < NUM_DIRS; i++)); do
    mount -t tmpfs tmpfs "/tmp/meow$i"
done

systemctl daemon-reload
systemctl list-units -t mount tmp-meow* | grep tmp-meow

for ((i = 0; i < NUM_DIRS; i++)); do
    umount "/tmp/meow$i"
done

# verify that we successfully entered and exited the rate limit state

timeout="$(date -ud "2 minutes" +%s)"
while [[ $(date -u +%s) -le $timeout ]]; do
    if journalctl -u init.scope | grep "(mount-monitor-dispatch) entered rate limit"; then
        break
    fi
    sleep 5
done

exited_rl=false
timeout="$(date -ud "2 minutes" +%s)"
while [[ $(date -u +%s) -le $timeout ]]; do
    if journalctl -u init.scope | grep "(mount-monitor-dispatch) left rate limit"; then
        exited_rl=true
        break
    fi
    sleep 5
done

if ! "$exited_rl"; then exit 24; fi

# verify that the mount units are cleaned up after we exit the rate limit state

systemctl daemon-reload
if systemctl list-units -t mount tmp-meow* | grep tmp-meow; then exit 42; fi

systemd-analyze log-level info

echo OK >/testok

exit 0
