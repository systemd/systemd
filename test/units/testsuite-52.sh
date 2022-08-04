#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

systemd-analyze log-level debug

systemctl enable test-honor-first-shutdown.service
systemctl start test-honor-first-shutdown.service

echo OK >/testok

exit 0
