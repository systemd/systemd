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
mkdir -p "$OUT_DIR"/{system,initrd}

run_for_cmdline() {
    if [[ "${2:?}" == "both" ]]; then
        run_for_cmdline "$1" system
        run_for_cmdline "$1" initrd
    else
        local cmdline="${1:?}"
        local out_dir="$OUT_DIR/${2:-system}"
        local in_initrd=$([ "${2:?}" != "initrd" ]; echo $?)

        SYSTEMD_IN_INITRD="$in_initrd" SYSTEMD_PROC_CMDLINE="$cmdline" run_and_list "$GENERATOR_BIN" "$out_dir"
    fi
}

# read-only is ignored by the generator for root and usr in initrd
run_for_cmdline "ro root=gpt-auto" initrd
(! grep -qE "^ExecStart=.*'(.+,)?read-only(,|')" "$OUT_DIR/initrd/late/systemd-cryptsetup@root.service" )
grep -qE "^ExecStart=.+ attach '.*' '/dev/gpt-auto-root-luks' '.*' '.*'$" "$OUT_DIR/initrd/late/systemd-cryptsetup@root.service"
grep -qE "^BindsTo=dev-gpt\\\x2dauto\\\x2droot\\\x2dluks.device$" "$OUT_DIR/initrd/late/systemd-cryptsetup@root.service"

# test luks-ignore-factory-reset

# both dissect and gpt-auto create systemd-cryptsetup@.service in initrd
# but these survive switch-root and thus are not created in system mode
run_for_cmdline "ro root=gpt-auto rootfstype=crypto_LUKS" both
test -f "$OUT_DIR"/initrd/late/systemd-cryptsetup@root.service
(! test -f "$OUT_DIR"/system/late/systemd-cryptsetup@root.service )

run_for_cmdline "rw root=dissect mount.usr=dissect" both
test -f "$OUT_DIR"/initrd/late/systemd-cryptsetup@usr.service
test -f "$OUT_DIR"/initrd/late/systemd-cryptsetup@root.service
(! test -f "$OUT_DIR"/system/late/systemd-cryptsetup@usr.service )
(! test -f "$OUT_DIR"/system/late/systemd-cryptsetup@root.service )

# crypto_LUKS as fstype results in the service being created after initrd again
run_for_cmdline "rw root=dissect rootfstype=crypto_LUKS mount.usr=dissect mount.usrfstype=crypto_LUKS" both
(! test -f "$OUT_DIR"/system/late/systemd-cryptsetup@usr.service )
(! test -f "$OUT_DIR"/system/late/systemd-cryptsetup@root.service )

# mount.crypt.interactive_recovery=no turns on headless-recovery and adds a OnFailure target
run_for_cmdline "rw root=dissect mount.usr=dissect rootfstype=crypto_LUKS mount.crypt.interactive_recovery=no" both
grep -qE "^OnFailure=decryption-failure@usr.target" "$OUT_DIR/initrd/late/systemd-cryptsetup@usr.service"
grep -qE "^ExecStart=.*'(.+,)?headless-recovery(,|')" "$OUT_DIR/initrd/late/systemd-cryptsetup@usr.service"
