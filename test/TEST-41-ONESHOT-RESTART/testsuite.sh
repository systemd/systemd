#!/bin/bash
set -ex
set -o pipefail

systemd-analyze log-level debug
systemd-analyze log-target console

# These three commands should succeed.
! systemd-run --unit=one -p Type=oneshot -p Restart=on-failure /bin/bash -c "exit 1"

sleep 5

if [[ "$(systemctl show one.service -p NRestarts --value)" -le 0 ]]; then
  exit 1
fi

TMP_FILE="/test-41-oneshot-restart-test"

touch $TMP_FILE

! systemd-run --unit=two -p StartLimitBurst=3 -p Type=oneshot -p Restart=on-failure -p ExecStart="/bin/bash -c \"printf a >>  $TMP_FILE\"" /bin/bash -c "exit 1"

sleep 5

if [[ $(cat $TMP_FILE) != "aaa" ]]; then
  exit 1
fi

systemd-analyze log-level info

echo OK > /testok

exit 0
