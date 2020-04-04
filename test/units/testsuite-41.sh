#!/usr/bin/env bash
set -ex
set -o pipefail

# wait this many secs for each test service to succeed in what is being tested
MAX_SECS=60

systemd-analyze log-level debug
systemd-analyze log-target console

# test one: Restart=on-failure should restart the service
! systemd-run --unit=one -p Type=oneshot -p Restart=on-failure /bin/bash -c "exit 1"

for ((secs=0; secs<$MAX_SECS; secs++)); do
  [[ "$(systemctl show one.service -P NRestarts)" -le 0 ]] || break
  sleep 1
done
if [[ "$(systemctl show one.service -P NRestarts)" -le 0 ]]; then
  exit 1
fi

TMP_FILE="/tmp/test-41-oneshot-restart-test"

: >$TMP_FILE

# test two: make sure StartLimitBurst correctly limits the number of restarts
# and restarts execution of the unit from the first ExecStart=
! systemd-run --unit=two -p StartLimitIntervalSec=120 -p StartLimitBurst=3 -p Type=oneshot -p Restart=on-failure -p ExecStart="/bin/bash -c \"printf a >>  $TMP_FILE\"" /bin/bash -c "exit 1"

# wait for at least 3 restarts
for ((secs=0; secs<$MAX_SECS; secs++)); do
  [[ $(cat $TMP_FILE) != "aaa" ]] || break
  sleep 1
done
if [[ $(cat $TMP_FILE) != "aaa" ]]; then
  exit 1
fi

# wait for 5 more seconds to make sure there aren't excess restarts
sleep 5
if [[ $(cat $TMP_FILE) != "aaa" ]]; then
  exit 1
fi

systemd-analyze log-level info

echo OK > /testok

exit 0
