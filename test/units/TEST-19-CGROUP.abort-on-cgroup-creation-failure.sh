#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

# Test that the service is not invoked if the cgroup cannot be created.

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
