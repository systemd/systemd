#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

# Test that the service is not invoked if the cgroup cannot be created.

# It seems openSUSE kernel (at least kernel-default-6.16.8-1.1.x86_64.rpm) has a
# bag in kernel oom killer or clone3 syscall, and spawning executor on a cgroup
# with too small MemoryMax= triggers infinite loop of OOM kill, and posix_spawn()
# will never return, and the service manager will stuck.
####
# [  119.776797] systemd invoked oom-killer: gfp_mask=0xcc0(GFP_KERNEL), order=0, oom_score_adj=0
# [  119.776859] CPU: 1 UID: 0 PID: 1472 Comm: systemd Not tainted 6.16.8-1-default #1 PREEMPT(voluntary) openSUSE Tumbleweed  6c85865973e4ae641870ed68afe8933a6986c974
# [  119.776865] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.17.0-5.fc42 04/01/2014
# [  119.776867] Call Trace:
# (snip)
# [  119.778126] Out of memory and no killable processes...
####
# On other distributions, the oom killer is triggered, but clone3 immediately
# fails with ENOMEM, and such problematic loop does not happen.
. /etc/os-release
if [[ "$ID" =~ opensuse ]]; then
    echo "Skipping cgroup test with too small MemoryMax= setting on openSUSE."
    exit 0
fi

cat >/run/systemd/system/testslice.slice <<EOF
[Slice]
MemoryMax=1
EOF

cat >/run/systemd/system/testservice.service <<EOF
[Service]
Type=oneshot
ExecStart=cat /proc/self/cgroup
Slice=testslice.slice
EOF

systemctl daemon-reload
(! systemctl start testservice.service)

rm /run/systemd/system/testslice.slice
rm /run/systemd/system/testservice.service

exit 0
