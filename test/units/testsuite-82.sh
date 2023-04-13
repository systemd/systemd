#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/assert.sh
. "$(dirname "$0")"/assert.sh

export SYSTEMD_LOG_LEVEL=debug

# Create service with KillMode=none inside a slice
cat <<EOF > /run/systemd/system/test82.service
[Unit]
Description=Test 82 Service
[Service]
Slice=test82.slice
Type=simple
ExecStart=sleep infinity
KillMode=none
EOF
cat <<EOF >/run/systemd/system/test82.slice
[Unit]
Description=Test 82 Slice
EOF

# Start service
systemctl start test82.service
assert_rc 0 systemd-cgls /test82.slice

# Stop slice
# The sleep process will not be killed because of KillMode=none
# Since there is still a process running under it, the /test82.slice cgroup won't be removed
systemctl stop test82.slice

# Kill sleep process manually
pkill sleep

assert_rc 1 systemd-cgls /test82.slice/test82.service

# Check that empty cgroup /test82.slice has been removed
timeout 30 bash -c 'while systemd-cgls /test82.slice >& /dev/null; do sleep .5; done'
assert_rc 1 systemd-cgls /test82.slice

# End
touch /testok
