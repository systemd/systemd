#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

systemd-analyze log-level debug

cat >/run/systemd/system/floodme@.service <<EOF
[Service]
ExecStart=true
EOF

cat >/run/systemd/system/floodme.socket <<EOF
[Socket]
ListenStream=/tmp/floodme
PollLimitIntervalSec=10s
Accept=yes
PollLimitBurst=3
EOF

systemctl daemon-reload
systemctl start floodme.socket

START=$(date +%s%N)

# Trigger this 100 times in a flood
for _ in {1..100}; do
    logger -u /tmp/floodme foo &
done

# Let some time pass
sleep 5

END=$(date +%s%N)

PASSED=$((END-START))

# Calculate (round up) how many trigger events could have happened in the passed time
MAXCOUNT=$(((PASSED+10000000000)*3/10000000000))

# We started 100 connection attempts, but only 3 should have gone through, as per limit
test "$(systemctl show -P NAccepted floodme.socket)" -le "$MAXCOUNT"

systemctl stop floodme.socket floodme@*.service

rm /run/systemd/system/floodme@.service /run/systemd/system/floodme.socket /tmp/floodme

systemctl daemon-reload
