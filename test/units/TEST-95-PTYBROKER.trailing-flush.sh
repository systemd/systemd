#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Regression test: terminal output that ends without a line terminator must still be
# flushed — in broker-log mode to the journal — when the PTY is hung up. This used to
# make systemd-ptybrokerd spin forever in its line-processing loop.

# Bounded, so that a regression fails right here rather than hanging until the global test timeout
timeout 30 systemd-pty-forward --quiet --console=broker-log --pty-name=pty95-flush -- \
    sh -c 'printf hello-pty95-flush-marker'

timeout 30 bash -c 'until journalctl -q -t pty95-flush | grep hello-pty95-flush-marker >/dev/null; do journalctl --sync; sleep 1; done'

# The daemon must still be alive and functional afterwards
ptyctl list
