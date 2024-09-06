#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

RESULTS_FILE=/tmp/TEST-66-DEVICE-ISOLATION.serviceresults

systemd-analyze log-level debug

systemctl start TEST-66-DEVICE-ISOLATION-device-isolation.service

sleep 5
grep -q "Operation not permitted" "$RESULTS_FILE"

systemctl daemon-reload
systemctl daemon-reexec

systemctl stop TEST-66-DEVICE-ISOLATION-device-isolation.service

grep -q "thisshouldnotbehere" "$RESULTS_FILE" && exit 42

systemd-analyze log-level info

touch /testok
