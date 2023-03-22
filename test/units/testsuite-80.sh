#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/assert.sh
. "$(dirname "$0")"/assert.sh

export SYSTEMD_LOG_LEVEL=debug

# Create service with KillMode=none inside a slice
cat <<EOF > /run/systemd/system/test80.service
[Unit]
Description=Test 80 Service
[Service]
Slice=test80.slice
Type=simple
ExecStart=sleep infinity
KillMode=none
EOF
cat <<EOF >/run/systemd/system/test80.slice
[Unit]
Description=Test 80 Slice
EOF

# Start service
systemctl start test80.service
assert_rc 0 systemd-cgls /test80.slice

# Stop slice
# The sleep process will not be killed because of KillMode=none
# Since there is still a process running under it, the /test80.slice cgroup won't be removed
systemctl stop test80.slice

# Kill sleep process manually
pkill sleep

# Check that empty cgroup /test80.slice has been removed
timeout 30 bash -c 'while systemd-cgls /test80.slice >& /dev/null; do sleep .5; done'
assert_rc 1 systemd-cgls /test80.slice

# End
touch /testok
