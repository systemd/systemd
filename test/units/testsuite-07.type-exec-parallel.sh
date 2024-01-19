#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Make sure that we never mistake a process starting but failing quickly for a process failing to start, with Type=exec.
# See https://github.com/systemd/systemd/pull/30799

seq 25 | xargs -n 1 -P 0 systemd-run -p Type=exec /bin/false
