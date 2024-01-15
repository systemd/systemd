#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# XXX needs hierarchy clarification
echo "SKIPPED"
exit

# Make sure ControlGroup= property points to the latest generation
systemctl --no-pager show --property=ControlGroup testsuite-99-restart-mode.service | grep -q 'ControlGroup=/system.slice/testsuite-99-restart-mode.service/2'

# Check that cgroup attributes set for the service are configured propertly (correctly exported and actually configured in cgroup fs)
systemctl set-property testsuite-99-restart-mode.service CPUWeight=200
systemctl show --property CPUWeight testsuite-99-restart-mode.service | grep -q 'CPUWeight=200'
grep -q 200 /sys/fs/cgroup/system.slice/testsuite-99-restart-mode.service/cpu.weight
