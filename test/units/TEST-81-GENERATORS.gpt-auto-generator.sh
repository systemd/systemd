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

run_for_cmdline() {
    local cmdline="${1:?}"
    local out_dir="$OUT_DIR/${2:-main}"
    local in_initrd=$([ "${2:?}" != "initrd" ]; echo $?)

    SYSTEMD_IN_INITRD="$in_initrd" SYSTEMD_PROC_CMDLINE="$cmdline" run_and_list "$GENERATOR_BIN" "$out_dir"
}

compare_initrd_main() {
    local cmdline="${1:?}"
    local mount_id="${2:?}"

    run_for_cmdline "$cmdline"
    run_for_cmdline "$cmdline" initrd

    test -f "$OUT_DIR"/main/late/systemd-cryptsetup@"$mount_id".service
    test -f "$OUT_DIR"/initrd/late/systemd-cryptsetup@"$mount_id".service
    diff "$OUT_DIR"/main/late/systemd-cryptsetup@"$mount_id".service "$OUT_DIR"/initrd/late/systemd-cryptsetup@"$mount_id".service
}

run_for_cmdline "ro root=gpt-auto" initrd
(! grep -qE "^ExecStart=(.+,)?read-only(,|$)" "$OUT_DIR/initrd/late/systemd-cryptsetup@root.service")

compare_initrd_main "rw root=gpt-auto rootfstype=crypto_LUKS" "root"
compare_initrd_main "ro root=dissect rootfstype=crypto_LUKS" "root"

compare_initrd_main "ro root=dissect mount.usr=dissect mount.usrfstype=crypto_LUKS" "usr"
compare_initrd_main "rw root=dissect rootfstype=crypto_LUKS mount.usr=dissect mount.usrfstype=crypto_LUKS" "usr"
compare_initrd_main "ro root=dissect rootfstype=crypto_LUKS mount.usr=dissect" "usr"

compare_initrd_main "rw root=dissect mount.usr=dissect" "root"
compare_initrd_main "rw root=dissect mount.usr=dissect" "usr"

compare_initrd_main "rw root=dissect mount.usr=dissect mount.crypt.interactive_recovery=no" "root"
compare_initrd_main "rw root=dissect mount.usr=dissect mount.crypt.interactive_recovery=no" "usr"
grep -qE "^OnFailure=decryption-failure@usr" "$OUT_DIR/main/late/systemd-cryptsetup@usr.service"
grep -qE "^ExecStart=(.+,)?headless-recovery(,|$)" "$OUT_DIR/main/late/systemd-cryptsetup@usr.service"
