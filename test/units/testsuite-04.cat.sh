#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

systemctl enable --now systemd-journald@cat-test.socket

systemd-cat --namespace cat-test env CAT_TEST_RESULT=1

systemctl disable --now systemd-journald@cat-test.socket

journalctl --namespace cat-test --grep "JOURNAL_STREAM="
journalctl --namespace cat-test --grep "CAT_TEST_RESULT=1"
