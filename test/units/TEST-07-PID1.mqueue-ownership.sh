#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Verify ownership attributes are applied to message queues

# Select arbitrary non-default attributes to apply to the queue.
queue=/attr_q  # Pick any unused queue name.
user=nobody  # Choose a core system user.
group=adm  # Choose a core system group.
mode=0420  # Allow the owner to read messages and anyone in the group to write.

at_exit() {
    set +e
    systemctl stop mqueue-ownership.{service,socket}
    rm -f /run/systemd/system/mqueue-ownership.{service,socket}
    systemctl daemon-reload
}
trap at_exit EXIT

cat << EOF > /run/systemd/system/mqueue-ownership.socket
[Unit]
Description=Create a message queue with customized ownership
[Socket]
ListenMessageQueue=/${queue#/}
RemoveOnStop=true
SocketUser=$user
SocketGroup=$group
SocketMode=$mode
EOF

cat << 'EOF' > /run/systemd/system/mqueue-ownership.service
[Unit]
Description=Dummy service for the socket unit
Requires=%N.socket
[Service]
ExecStart=/usr/bin/true
Type=oneshot
EOF

systemctl daemon-reload
systemctl start mqueue-ownership.socket

systemctl start dev-mqueue.mount  # Ensure this file path interface is mounted.
[[ $(stat -c '%04a %U %G' "/dev/mqueue/${queue#/}") == "$mode $user $group" ]]
