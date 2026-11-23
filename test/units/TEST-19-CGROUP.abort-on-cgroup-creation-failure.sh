#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

# Test that the service is not invoked if the cgroup cannot be created.

cat >/run/systemd/system/testslice.slice <<EOF
[Slice]
MemoryMax=1
EOF

# Enable memory accounting explicitly, so that the memory controller is enabled in the
# parent slice's subtree_control and creating our cgroup requires a memcg css allocation
# charged to the slice. This must not depend on DefaultMemoryAccounting=, which distros
# may default to no (e.g. openSUSE): without the controller, the cgroup is created
# without any charge, and starting the service then runs into a kernel bug:
#
# The executor is cloned with CLONE_VM|CLONE_VFORK|CLONE_INTO_CGROUP directly into the
# MemoryMax=1 slice. When the first page fault of the child cannot be charged, the memcg
# OOM killer cannot select the child as a victim, because tasks in the middle of a vfork
# are excluded from victim selection (killing them would not free the mm shared with the
# parent). The charge keeps failing, userspace retries the fault over and over, and the
# parent — the service manager — never returns from clone3().
cat >/run/systemd/system/testservice.service <<EOF
[Service]
Type=oneshot
ExecStart=cat /proc/self/cgroup
MemoryAccounting=yes
Slice=testslice.slice
EOF

systemctl daemon-reload
(! systemctl start testservice.service)

rm /run/systemd/system/testslice.slice
rm /run/systemd/system/testservice.service

exit 0
