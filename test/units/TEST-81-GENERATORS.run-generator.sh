#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2235
set -eux
set -o pipefail

# shellcheck source=test/units/generator-utils.sh
. "$(dirname "$0")/generator-utils.sh"

GENERATOR_BIN="/usr/lib/systemd/system-generators/systemd-run-generator"
OUT_DIR="$(mktemp -d /tmp/run-generator.XXX)"

at_exit() {
    rm -frv "${OUT_DIR:?}"
}

trap at_exit EXIT

test -x "${GENERATOR_BIN:?}"

check_kernel_cmdline_target() {
    local out_dir="${1:?}/normal"

    cat "$out_dir/kernel-command-line.target"
    grep -qE "^Requires=kernel-command-line.service$" "$out_dir/kernel-command-line.target"
    grep -qE "^After=kernel-command-line.service$" "$out_dir/kernel-command-line.target"

    link_eq "$out_dir/default.target" "kernel-command-line.target"
}

: "run-generator: empty cmdline"
SYSTEMD_PROC_CMDLINE="" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
[[ "$(find "$OUT_DIR" ! -type d | wc -l)" -eq 0 ]]

: "run-generator: single command"
CMDLINE="systemd.run='echo hello world'"
SYSTEMD_PROC_CMDLINE="$CMDLINE" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
check_kernel_cmdline_target "$OUT_DIR"
UNIT="$OUT_DIR/normal/kernel-command-line.service"
cat "$UNIT"
systemd-analyze verify --man=no --recursive-errors=no "$UNIT"
grep -qE "^SuccessAction=exit$" "$UNIT"
grep -qE "^FailureAction=exit$" "$UNIT"
grep -qE "^ExecStart=echo hello world$" "$UNIT"

: "run-generator: multiple commands + success/failure actions"
ARGS=(
    # These should be ignored
    "systemd.run"
    "systemd.run_success_action"
    "systemd.run_failure_action"

    # Set actions which we will overwrite later
    "systemd.run_success_action="
    "systemd.run_failure_action="

    "systemd.run=/bin/false"
    "systemd.run="
    "systemd.run=/bin/true"
    "systemd.run='echo this is a long string'"

    "systemd.run_success_action=reboot"
    "systemd.run_failure_action=poweroff-force"
)
CMDLINE="${ARGS[*]}"
SYSTEMD_PROC_CMDLINE="$CMDLINE" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
check_kernel_cmdline_target "$OUT_DIR"
UNIT="$OUT_DIR/normal/kernel-command-line.service"
cat "$UNIT"
systemd-analyze verify --man=no --recursive-errors=no "$UNIT"
grep -qE "^SuccessAction=reboot$" "$UNIT"
grep -qE "^FailureAction=poweroff-force$" "$UNIT"
grep -qE "^ExecStart=/bin/false$" "$UNIT"
grep -qE "^ExecStart=$" "$UNIT"
grep -qE "^ExecStart=/bin/true$" "$UNIT"
grep -qE "^ExecStart=echo this is a long string$" "$UNIT"
