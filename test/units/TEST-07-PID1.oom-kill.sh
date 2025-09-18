#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/../units/util.sh

(! systemd-run --wait --unit oom-kill -p OOMPolicy=continue -p MemoryMax=20M --remain-after-exit bash -c 'dd if=/dev/zero of=/tmp/out bs=200M || dd if=/dev/zero of=/tmp/out bs=200M')
# With OOMPolicy=continue, we shouldn't get the oom-kill result.
assert_eq "$(systemctl show oom-kill -P Result)" "signal"
# Check that OOMKills reports 2 individual processes killed
assert_eq "$(systemctl show oom-kill -P OOMKills)" "2"
systemctl reset-failed

(! systemd-run --wait --unit oom-kill -p OOMPolicy=kill -p MemoryMax=20M bash -c 'dd if=/dev/zero of=/tmp/out bs=200M')
# Check that a regular kernel oom kill with OOMPolicy=kill results in the oom-kill result
assert_eq "$(systemctl show oom-kill -P Result)" "oom-kill"
# Check that OOMKills reports 1 oom group kill instead of the number of processes that were killed
assert_eq "$(systemctl show oom-kill -P OOMKills)" "1"
systemctl reset-failed

cat >/tmp/script.sh <<"EOF"
#!/bin/bash
echo '+memory' >/sys/fs/cgroup/system.slice/oom-kill.service/cgroup.subtree_control
mkdir /sys/fs/cgroup/system.slice/oom-kill.service/sub
echo 1 >/sys/fs/cgroup/system.slice/oom-kill.service/sub/memory.oom.group
echo 20000000 >/sys/fs/cgroup/system.slice/oom-kill.service/sub/memory.max
echo $$>/sys/fs/cgroup/system.slice/oom-kill.service/sub/cgroup.procs
dd if=/dev/zero of=/tmp/out bs=200M
EOF
chmod +x /tmp/script.sh

(! systemd-run --wait --unit oom-kill -p OOMPolicy=kill -p Delegate=yes -p DelegateSubgroup=init.scope /tmp/script.sh)
# Test that an oom-kill in a delegated unit in a subcgroup with memory.oom.group=1 does *not* result in the
# oom-kill exit status.
assert_eq "$(systemctl show oom-kill -P Result)" "signal"
# Test that we don't record any oom kills in the OOMKills property in this case either.
assert_eq "$(systemctl show oom-kill -P OOMKills)" "0"
systemctl reset-failed
