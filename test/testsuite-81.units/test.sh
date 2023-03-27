#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

systemd-notify --status="Test starts, setting up test environment"
# Set up test environment here, e.g., create loopback devices, LUKS containers, etc.

(
    systemd-notify --pid=auto
    systemd-notify "CRYPTENROLL=main"

    systemd-notify --status="Enrolling recovery key"
    # Enroll recovery key and perform related tests here

    sleep 10
    systemd-notify "MAINPID=$$"
)

systemd-notify --ready --status="Testing key generation and decoding"
# Test key generation and decoding here, e.g., test decode_modhex_char function

systemd-notify "CRYPTENROLL=none"
sleep 5

systemd-notify --ready --status="Cleaning up test environment"
# Clean up test environment here, e.g., close LUKS containers, remove loopback devices, etc.

systemd-notify "CRYPTENROLL=done"
sleep infinity
