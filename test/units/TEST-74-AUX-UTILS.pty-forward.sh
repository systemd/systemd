#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

systemd-pty-forward --background 41 --title test echo foobar
