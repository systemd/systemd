#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# Test oneshot unit restart on failure

# wait this many secs for each test service to succeed in what is being tested
MAX_SECS=60

systemctl log-level debug

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

# Test RestartForceExitStatus=. Note that success exit statuses are meant to be skipped

TMP_FILE="/tmp/test-23-oneshot-restart-test$RANDOM"
UNIT_NAME="TEST-23-UNIT-FILE-oneshot-restartforce.service"
ONSUCCESS_UNIT_NAME="TEST-23-UNIT-FILE-oneshot-restartforce-onsuccess.service"
FIFO_FILE="/tmp/test-23-oneshot-restart-test-fifo"

cat >"/run/systemd/system/$UNIT_NAME" <<EOF
[Unit]
OnSuccess=$ONSUCCESS_UNIT_NAME

[Service]
Type=oneshot
RestartForceExitStatus=0 2
ExecStart=/usr/lib/systemd/tests/testdata/TEST-23-UNIT-FILE.units/TEST-23-UNIT-FILE-oneshot-restartforce.sh "$TMP_FILE"

[Install]
WantedBy=multi-user.target
EOF

cat >"/run/systemd/system/$ONSUCCESS_UNIT_NAME" <<EOF
[Service]
Type=oneshot
ExecStart=bash -c 'echo finished >$FIFO_FILE'
EOF

mkfifo "$FIFO_FILE"

# Pin the unit in memory
systemctl enable "$UNIT_NAME"
# Initial run should fail
(! systemctl start "$UNIT_NAME")
# Wait for OnSuccess=
read -r x <"$FIFO_FILE"
assert_eq "$x" "finished"

cmp -b <(systemctl show "$UNIT_NAME" -p Result -p NRestarts -p SubState) <<EOF
Result=success
NRestarts=1
SubState=dead
EOF

systemctl disable "$UNIT_NAME"
rm "$TMP_FILE" /run/systemd/system/{"$UNIT_NAME","$ONSUCCESS_UNIT_NAME"} "$FIFO_FILE"

systemctl log-level info
