#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Test that KillMode=mixed does not leave left over processes with ExecStopPost=
# Issue: https://github.com/systemd/systemd/issues/14566

rm -f /run/leakedtestpid
systemctl start issue14566-repro
systemctl status issue14566-repro

leaked_pid=$(cat /run/leakedtestpid)

systemctl stop issue14566-repro
timeout 30 bash -c 'while systemctl is-active issue14566-repro; do sleep .5; done'

# Leaked PID will still be around if we're buggy.
# I personally prefer to see 42.
ps -p "$leaked_pid" && exit 42

exit 0
