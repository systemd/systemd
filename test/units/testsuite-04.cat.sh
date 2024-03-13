#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

systemctl enable --now systemd-journald@cat-test.socket

systemd-cat --namespace cat-test env CAT_TEST_RESULT=1

timeout 30 bash -c "until systemctl -q is-active systemd-journald@cat-test.service; do sleep .5; done"

journalctl --namespace cat-test --grep "JOURNAL_STREAM="
journalctl --namespace cat-test --grep "CAT_TEST_RESULT=1"

systemctl disable --now systemd-journald@cat-test.socket
