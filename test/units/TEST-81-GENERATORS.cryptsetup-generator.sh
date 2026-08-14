#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/generator-utils.sh
. "$(dirname "$0")/generator-utils.sh"

GENERATOR_BIN="${GENERATOR_BIN:-/usr/lib/systemd/system-generators/systemd-cryptsetup-generator}"
OUT_DIR="$(mktemp -d /tmp/cryptsetup-generator.XXX)"

at_exit() {
    rm -fr "${OUT_DIR:?}"
}

trap at_exit EXIT

test -x "${GENERATOR_BIN:?}"

check_no_cryptsetup_units() {
    test -z "$(find "$OUT_DIR" -type f -name 'systemd-cryptsetup@*.service' -print -quit)"
    test -z "$(find "$OUT_DIR" -type l -name 'systemd-cryptsetup@*.service' -print -quit)"
}

UUID="b40f1abf-2a53-400a-889a-2eccc27eaa40"

SYSTEMD_CRYPTTAB=/dev/null SYSTEMD_PROC_CMDLINE="luks.uuid=$UUID" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
test -e "$OUT_DIR/normal/systemd-cryptsetup@luks\\x2db40f1abf\\x2d2a53\\x2d400a\\x2d889a\\x2d2eccc27eaa40.service"

SYSTEMD_CRYPTTAB=/dev/null SYSTEMD_PROC_CMDLINE="luks.uuid=not-a-uuid" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
check_no_cryptsetup_units

SYSTEMD_CRYPTTAB=/dev/null SYSTEMD_PROC_CMDLINE="luks.name=deadbeef=root" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
check_no_cryptsetup_units
