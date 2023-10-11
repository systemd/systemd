#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# For issue https://github.com/systemd/systemd/issues/29526
systemd-run -p PrivateNetwork=yes --wait /bin/true
