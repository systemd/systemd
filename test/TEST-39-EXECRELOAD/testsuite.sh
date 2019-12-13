#!/bin/bash

set -ex
set -o pipefail

systemd-analyze log-level debug
systemd-analyze log-target console

export SYSTEMD_PAGER=
SERVICE_PATH="$(mktemp /etc/systemd/system/execreloadXXX.service)"
SERVICE_NAME="${SERVICE_PATH##*/}"

echo "[#1] Failing ExecReload= should not kill the service"
cat > "$SERVICE_PATH" << EOF
[Service]
ExecStart=/bin/sleep infinity
ExecReload=/bin/false
EOF

systemctl daemon-reload
systemctl start $SERVICE_NAME
systemctl status $SERVICE_NAME
# The reload SHOULD fail but SHOULD NOT affect the service state
! systemctl reload $SERVICE_NAME
systemctl status $SERVICE_NAME
systemctl stop $SERVICE_NAME


echo "[#2] Failing ExecReload= should not kill the service (multiple ExecReload=)"
cat > "$SERVICE_PATH" << EOF
[Service]
ExecStart=/bin/sleep infinity
ExecReload=/bin/true
ExecReload=/bin/false
ExecReload=/bin/true
EOF

systemctl daemon-reload
systemctl start $SERVICE_NAME
systemctl status $SERVICE_NAME
# The reload SHOULD fail but SHOULD NOT affect the service state
! systemctl reload $SERVICE_NAME
systemctl status $SERVICE_NAME
systemctl stop $SERVICE_NAME

echo "[#3] Failing ExecReload=- should not affect reload's exit code"
cat > "$SERVICE_PATH" << EOF
[Service]
ExecStart=/bin/sleep infinity
ExecReload=-/bin/false
EOF

systemctl daemon-reload
systemctl start $SERVICE_NAME
systemctl status $SERVICE_NAME
systemctl reload $SERVICE_NAME
systemctl status $SERVICE_NAME
systemctl stop $SERVICE_NAME

systemd-analyze log-level info

echo OK > /testok

exit 0
