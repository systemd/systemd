#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

RESULTS_FILE=/tmp/testsuite66serviceresults

systemd-analyze log-level debug

systemctl start testsuite-66-deviceisolation.service

sleep 5
grep -q "Operation not permitted" "$RESULTS_FILE"

systemctl daemon-reload
systemctl daemon-reexec

systemctl stop testsuite-66-deviceisolation.service

grep -q "thisshouldnotbehere" "$RESULTS_FILE" && exit 42

systemd-analyze log-level info

echo OK >/testok

exit 0
