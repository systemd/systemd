#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Test oneshot unit restart on failure

# wait this many secs for each test service to succeed in what is being tested
MAX_SECS=60

systemd-analyze log-level debug

# test one: Restart=on-failure should restart the service
(! systemd-run --unit=oneshot-restart-one -p Type=oneshot -p Restart=on-failure /bin/bash -c "exit 1")

for ((secs = 0; secs < MAX_SECS; secs++)); do
    [[ "$(systemctl show oneshot-restart-one.service -P NRestarts)" -le 0 ]] || break
    sleep 1
done
if [[ "$(systemctl show oneshot-restart-one.service -P NRestarts)" -le 0 ]]; then
    exit 1
fi

TMP_FILE="/tmp/test-23-oneshot-restart-test$RANDOM"

: >$TMP_FILE

# test two: make sure StartLimitBurst correctly limits the number of restarts
# and restarts execution of the unit from the first ExecStart=
(! systemd-run --unit=oneshot-restart-two \
        -p StartLimitIntervalSec=120 \
        -p StartLimitBurst=3 \
        -p Type=oneshot \
        -p Restart=on-failure \
        -p ExecStart="/bin/bash -c 'printf a >>$TMP_FILE'" /bin/bash -c "exit 1")

# wait for at least 3 restarts
for ((secs = 0; secs < MAX_SECS; secs++)); do
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
rm "$TMP_FILE"

TMP_FILE="/tmp/test-23-oneshot-restart-test$RANDOM"

cat >/run/systemd/system/testsuite-23-oneshot-restartforce.service <<EOF
[Service]
Type=oneshot
RestartForceExitStatus=0 2
RemainAfterExit=yes
ExecStart=/usr/lib/systemd/tests/testdata/testsuite-23.units/testsuite-23-oneshot-restartforce.sh "$TMP_FILE"
EOF

(! systemctl start testsuite-23-oneshot-restartforce.service)
sleep 5
systemctl is-active testsuite-23-oneshot-restartforce.service
assert_eq "$(systemctl show testsuite-23-oneshot-restartforce.service -P Result)" "success"
assert_eq "$(systemctl show testsuite-23-oneshot-restartforce.service -P NRestarts)" "1"

rm "$TMP_FILE" /run/systemd/system/testsuite-23-oneshot-restartforce.service

systemd-analyze log-level info
