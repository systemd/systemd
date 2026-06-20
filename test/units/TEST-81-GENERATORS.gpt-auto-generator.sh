#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2235,SC2233
set -eux
set -o pipefail

# shellcheck source=test/units/generator-utils.sh
. "$(dirname "$0")/generator-utils.sh"

GENERATOR_BIN="/usr/lib/systemd/system-generators/systemd-gpt-auto-generator"
OUT_DIR="$(mktemp -d /tmp/gpt-auto-generator.XXX)"

at_exit() {
    rm -fr "${OUT_DIR:?}"
}

trap at_exit EXIT

test -x "${GENERATOR_BIN:?}"
mkdir -p "$OUT_DIR"/{main,initrd}

compare_initrd_main() {
    local cmdline="${1:?}"
    local out_dir="${2:?}"
    local mount_id="${3:?}"

    SYSTEMD_IN_INITRD=0 SYSTEMD_PROC_CMDLINE="$cmdline" run_and_list "$GENERATOR_BIN" "$out_dir"/main
    SYSTEMD_IN_INITRD=1 SYSTEMD_PROC_CMDLINE="$cmdline" run_and_list "$GENERATOR_BIN" "$out_dir"/initrd

    test -f "$out_dir"/main/late/systemd-cryptsetup@"$mount_id".service
    test -f "$out_dir"/initrd/late/systemd-cryptsetup@"$mount_id".service
    diff "$out_dir"/main/late/systemd-cryptsetup@"$mount_id".service "$out_dir"/initrd/late/systemd-cryptsetup@"$mount_id".service

}

compare_initrd_main "ro root=gpt-auto" "$OUT_DIR" "root"
grep -qE "^ExecStart=(.+,)?read-only(,|$)" "$OUT_DIR/main/late/systemd-cryptsetup@root.service"

compare_initrd_main "rw root=gpt-auto rootfstype=crypto_LUKS" "$OUT_DIR" "root"
grep -qE "^ExecStart=(.+,)?read-only(,|$)" "$OUT_DIR/main/late/systemd-cryptsetup@root.service"

compare_initrd_main "ro root=dissect rootfstype=crypto_LUKS" "$OUT_DIR" "root"
compare_initrd_main "ro root=dissect mount.usr=dissect mount.usrfstype=crypto_LUKS" "$OUT_DIR" "usr"

compare_initrd_main "rw root=dissect rootfstype=crypto_LUKS mount.usr=dissect mount.usrfstype=crypto_LUKS" "$OUT_DIR" "usr"
compare_initrd_main "ro root=dissect rootfstype=crypto_LUKS mount.usr=dissect" "$OUT_DIR" "usr"

compare_initrd_main "rw root=dissect mount.usr=dissect" "$OUT_DIR" "root"
compare_initrd_main "rw root=dissect mount.usr=dissect" "$OUT_DIR" "usr"

compare_initrd_main "rw root=dissect mount.usr=dissect mount.crypt.interactive_recovery=no" "$OUT_DIR" "root"
compare_initrd_main "rw root=dissect mount.usr=dissect mount.crypt.interactive_recovery=no" "$OUT_DIR" "usr"
grep -qE "^OnFailure=decryption-failure@usr" "$OUT_DIR/main/late/systemd-cryptsetup@usr.service"
grep -qE "^ExecStart=(.+,)?headless-recovery(,|$)" "$OUT_DIR/main/late/systemd-cryptsetup@usr.service"

compare_initrd_main "rw root=dissect rootfstype=crypto_LUKS mount.usr=dissect mount.crypt.interactive_recovery=no" "$OUT_DIR" "root"
compare_initrd_main "rw root=dissect rootfstype=crypto_LUKS mount.usr=dissect mount.crypt.interactive_recovery=no" "$OUT_DIR" "usr"
