#!/usr/bin/env bash
set -ex
set -o pipefail

fail () {
    systemd-analyze log-level info
    exit 1
}

systemd-analyze log-level debug
systemd-analyze log-target console

cat >/run/systemd/system/testservice-fail-57.service <<EOF
[Unit]
Description=TEST-57-RELOADING-RESTART Restart=on-failure

[Service]
Type=notify
ExecStart=/bin/bash -c "systemd-notify --ready; systemd-notify RELOADING=1; sleep 1; exit 1"
Restart=on-failure
StartLimitBurst=1
EOF


cat >/run/systemd/system/testservice-abort-57.service <<EOF
[Unit]
Description=TEST-57-RELOADING-RESTART Restart=on-abort

[Service]
Type=notify
ExecStart=/bin/bash -c "systemd-notify --ready; systemd-notify RELOADING=1; sleep 3; exit 1"
Restart=on-abort
StartLimitBurst=1
EOF

systemctl daemon-reload

# This service will sleep for 1s then exit with a non-zero exit code, it
# should not stay in reloading state. Rather, it should be restarted
# and finally end up in "failed" state after StartLimitBurst has been exceeded.
systemctl start testservice-fail-57.service
# Sleep for 4s to allow the service to start, exit, start, exit.
sleep 4
state=$(systemctl show testservice-fail-57.service --property=ActiveState --value)
if [ "$state" = "reloading" ]; then
    fail
fi

# This service will sleep for 3s to allow us to send it a SIGABRT.
systemctl start testservice-abort-57.service
pid=$(systemctl show testservice-abort-57.service --property=ExecMainPID --value)
kill -6 "$pid"
# Sleep long enough to allow the restart to complete and for the 2nd sleep to finish.
sleep 8
state=$(systemctl show testservice-abort-57.service --property=ActiveState --value)
if [ "$state" = "reloading" ]; then
    fail
fi

systemd-analyze log-level info

echo OK >/testok

exit 0
