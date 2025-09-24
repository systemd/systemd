#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

systemctl enable test-honor-first-shutdown.service
systemctl start test-honor-first-shutdown.service

touch /testok
