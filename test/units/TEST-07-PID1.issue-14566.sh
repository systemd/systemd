#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Test that KillMode=mixed does not leave left over processes with ExecStopPost=
# Issue: https://github.com/systemd/systemd/issues/14566

if [[ -v ASAN_OPTIONS ]]; then
    # Temporarily skip this test when running with sanitizers due to a deadlock
    # See: https://bugzilla.redhat.com/show_bug.cgi?id=2098125
    echo "Sanitizers detected, skipping the test..."
    exit 0
fi

systemctl start issue14566-repro
sleep 4
systemctl status issue14566-repro

leaked_pid=$(cat /leakedtestpid)

systemctl stop issue14566-repro
sleep 4

# Leaked PID will still be around if we're buggy.
# I personally prefer to see 42.
ps -p "$leaked_pid" && exit 42

exit 0
