#!/usr/bin/env bash
set -eux
set -o pipefail

systemd-analyze log-level debug
systemd-analyze log-target console

systemctl start testsuite-66-deviceisolation.service

grep -q "Operation not permitted" /testsuite66serviceresults

systemctl daemon-reload
systemctl daemon-reexec

systemctl stop testsuite-66-deviceisolation.service

grep -q "thisshouldnotbehere" /testsuite66serviceresults && exit 42

systemd-analyze log-level info

echo OK >/testok

exit 0
