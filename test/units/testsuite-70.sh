#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

if [ ! -f /sys/fs/cgroup/init.scope/cgroup.type ] ; then
	echo "cgroup v2 doesn't support cgroup.type" >/skipped
	exit 0
fi

systemd-analyze log-level debug
systemd-analyze log-target console

export SYSTEMD_PAGER=
SERVICE_PATH="$(mktemp /etc/systemd/system/test-delegate-XXX.service)"
SERVICE_NAME="${SERVICE_PATH##*/}"

cat >"$SERVICE_PATH" <<EOF
[Service]
Delegate=true
ExecStartPre=/bin/mkdir /sys/fs/cgroup/system.slice/$SERVICE_NAME/subtree
ExecStartPre=/bin/bash -c "echo threaded >/sys/fs/cgroup/system.slice/$SERVICE_NAME/subtree/cgroup.type"
ExecStart=/bin/sleep 86400
ExecReload=/bin/echo pretending to reload

EOF

systemctl daemon-reload
systemctl start "$SERVICE_NAME"
systemctl status "$SERVICE_NAME"
# The reload SHOULD succeed
systemctl reload "$SERVICE_NAME" || { echo 'unexpected reload failure'; exit 1; }
systemctl stop "$SERVICE_NAME"

systemd-analyze log-level info

rm -f $SERVICE_PATH

echo OK >/testok

exit 0
