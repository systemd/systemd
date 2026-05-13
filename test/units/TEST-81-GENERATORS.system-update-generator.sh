#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2235
set -eux
set -o pipefail

# shellcheck source=test/units/generator-utils.sh
. "$(dirname "$0")/generator-utils.sh"

GENERATOR_BIN="/usr/lib/systemd/system-generators/systemd-system-update-generator"
OUT_DIR="$(mktemp -d /tmp/system-update-generator-generator.XXX)"

at_exit() {
    rm -frv "${OUT_DIR:?}" /system-update
}

trap at_exit EXIT

test -x "${GENERATOR_BIN:?}"

rm -f /system-update

: "system-update-generator: no /system-update flag"
run_and_list "$GENERATOR_BIN" "$OUT_DIR"
[[ "$(find "$OUT_DIR" ! -type d | wc -l)" -eq 0 ]]

: "system-update-generator: with /system-update flag"
touch /system-update
run_and_list "$GENERATOR_BIN" "$OUT_DIR"
link_endswith "$OUT_DIR/early/default.target" "/lib/systemd/system/system-update.target"

: "system-update-generator: kernel cmdline warnings"
# We should warn if the default target is overridden on the kernel cmdline
# by a runlevel or systemd.unit=, but still generate the symlink
SYSTEMD_PROC_CMDLINE="systemd.unit=foo.bar 3" run_and_list "$GENERATOR_BIN" "$OUT_DIR" |& tee /tmp/system-update-generator.log
link_endswith "$OUT_DIR/early/default.target" "/lib/systemd/system/system-update.target"
grep -qE "Offline system update overridden .* systemd.unit=" /tmp/system-update-generator.log
grep -qE "Offline system update overridden .* runlevel" /tmp/system-update-generator.log
