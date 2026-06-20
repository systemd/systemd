#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2235,SC2233
set -eux
set -o pipefail

# shellcheck source=test/units/generator-utils.sh
. "$(dirname "$0")/generator-utils.sh"

GENERATOR_BIN="/usr/lib/systemd/system-generators/gpt-auto-generator"
OUT_DIR="$(mktemp -d /tmp/debug-generator.XXX)"

at_exit() {
    rm -fr "${OUT_DIR:?}"
}

trap at_exit EXIT

test -x "${GENERATOR_BIN:?}"

compare_early_normal() {
    local cmdline="${1:?}"
    local out_dir="${2:?}"
    local mount_id="${3:?}"

    SYSTEMD_IN_INITRD=0 SYSTEMD_PROC_CMDLINE="$cmdline" run_and_list "$GENERATOR_BIN" "$out_dir"
    SYSTEMD_IN_INITRD=1 SYSTEMD_PROC_CMDLINE="$cmdline" run_and_list "$GENERATOR_BIN" "$out_dir"

    test -f "$out_dir"/early/systemd-cryptsetup@"$mount_id".service
    test -f "$out_dir"/normal/systemd-cryptsetup@"$mount_id".service
    diff "$out_dir"/early/systemd-cryptsetup@"$mount_id".service "$out_dir"/normal/systemd-cryptsetup@"$mount_id".service
}

compare_early_normal "ro root=gpt-auto rootfstype=crypto_LUKS" "$OUT_DIR" "root"
compare_early_normal "rw root=gpt-auto rootfstype=crypto_LUKS" "$OUT_DIR" "root"

compare_early_normal "ro root=dissect rootfstype=crypto_LUKS" "$OUT_DIR" "root"

compare_early_normal "ro root=dissect mount.usr=dissect mount.usrfstype=crypto_LUKS" "$OUT_DIR" "usr"

compare_early_normal "rw root=dissect rootfstype=crypto_LUKS mount.usr=dissect mount.usrfstype=crypto_LUKS" "$OUT_DIR" "usr"
compare_early_normal "ro root=dissect rootfstype=crypto_LUKS mount.usr=dissect" "$OUT_DIR" "usr"

compare_early_normal "rw root=dissect mount.usr=dissect" "$OUT_DIR" "root"
compare_early_normal "rw root=dissect mount.usr=dissect" "$OUT_DIR" "usr"

compare_early_normal "rw root=dissect mount.usr=dissect mount.crypt.interactive_recovery" "$OUT_DIR" "root"
compare_early_normal "rw root=dissect mount.usr=dissect mount.crypt.interactive_recovery" "$OUT_DIR" "usr"

compare_early_normal "rw root=dissect rootfstype=crypto_LUKS mount.usr=dissect mount.crypt.interactive_recovery" "$OUT_DIR" "root"
compare_early_normal "rw root=dissect rootfstype=crypto_LUKS mount.usr=dissect mount.crypt.interactive_recovery" "$OUT_DIR" "usr"
