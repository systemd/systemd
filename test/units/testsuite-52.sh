#!/bin/bash
set -ex
set -o pipefail

systemd-analyze log-level debug
systemd-analyze log-target console

systemctl enable test-honor-first-shutdown.service
systemctl start test-honor-first-shutdown.service

echo OK >/testok

exit 0
