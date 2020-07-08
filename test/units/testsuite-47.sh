#!/usr/bin/env bash
set -ex
set -o pipefail

systemd-analyze log-level debug
systemd-analyze log-target console

systemctl start testsuite-47-repro
sleep 4
systemctl status testsuite-47-repro

leaked_pid=$(cat /leakedtestpid)

systemctl stop testsuite-47-repro
sleep 4

# Leaked PID will still be around if we're buggy.
# I personally prefer to see 42.
ps -p "$leaked_pid" && exit 42

systemd-analyze log-level info

echo OK > /testok

exit 0
