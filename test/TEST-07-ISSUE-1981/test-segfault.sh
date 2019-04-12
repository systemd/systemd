#!/bin/bash
set -x
set -e

>/failed

cat <<'EOL' >/lib/systemd/system/my.service
[Service]
Type=oneshot
ExecStart=/bin/echo Timer runs me
EOL

cat <<'EOL' >/lib/systemd/system/my.timer
[Timer]
OnBootSec=10s
OnUnitInactiveSec=1h
EOL

systemctl unmask my.timer

systemctl start my.timer

mkdir -p /etc/systemd/system/my.timer.d/
cat <<'EOL' >/etc/systemd/system/my.timer.d/override.conf
[Timer]
OnBootSec=10s
OnUnitInactiveSec=1h
EOL

systemctl daemon-reload

systemctl mask my.timer

touch /testok
rm /failed
