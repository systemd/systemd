#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2235
set -eux
set -o pipefail

GENERATOR_BIN="/usr/lib/systemd/system-generators/systemd-modules-load-generator"
CONFIG_FILE="/run/modules-load.d/99-test.conf"
OUT_DIR="$(mktemp -d /tmp/systemd-modules-load-generator.XXX)"

# shellcheck source=test/units/generator-utils.sh
. "$(dirname "$0")/generator-utils.sh"

at_exit() {
    rm -rfv "${CONFIG_FILE:?}"
    rm -frv "${OUT_DIR:?}"
}

trap at_exit EXIT

test -x "${GENERATOR_BIN:?}"

ORIG_MODULES_LOAD_CONFIG="$(systemd-analyze cat-config modules-load.d)"

# Count the number of modules contained inside the original config
ORIG_MODULES_NUM="$(systemd-analyze cat-config modules-load.d | sed -e '/^\s*#/d;/^\s*$/d' -e 's/-/_/g' | sort -u | wc -l)"

mkdir -p "$(dirname $CONFIG_FILE)"

check_modprobe_enabled() {
    unit="$(systemd-escape --template modprobe@.service "${1}" | sed 's/-/_/g')"
    link_endswith "$OUT_DIR/normal/modules-load.target.wants/$unit" "/lib/systemd/system/modprobe@.service"
}

check_modprobe_num() {
    expected_services=$(( $1 + ORIG_MODULES_NUM ))
    found_services=$(find "$OUT_DIR/normal/modules-load.target.wants/" -name "modprobe*.service" | wc -l)
    [[ "$found_services" == "$expected_services" ]]
}

# Simple config file
printf "dummy" >"$CONFIG_FILE"
run_and_list "$GENERATOR_BIN" "$OUT_DIR"
check_modprobe_enabled "dummy"

# Valid & invalid data mixed together
cat >"$CONFIG_FILE" <<EOF

dummy
dummy
dummy
    dummy
dummy
    \\n\n\n\\\\\\

dumm!@@123##2455
# This is a comment
dummy
dummy2
dummy-3
dummy_3
"
'
EOF
run_and_list "$GENERATOR_BIN" "$OUT_DIR"
check_modprobe_enabled "dummy"
check_modprobe_enabled "dummy2"
check_modprobe_enabled "dumm!@@123##2455"
check_modprobe_enabled "dummy_3"
# dummy_3 and dummy-3 are the same module
check_modprobe_num 4

# Command line arguments
# Make sure we have no config files left over that might interfere with
# following tests
rm -fv "$CONFIG_FILE"
[[ "$ORIG_MODULES_LOAD_CONFIG" == "$(systemd-analyze cat-config modules-load.d)" ]]
CMDLINE="ro root= modules_load= modules_load=, / = modules_load=dummy2,dummy modules_load=dummy,dummy,dummy"
SYSTEMD_PROC_CMDLINE="${CMDLINE}" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
check_modprobe_enabled "dummy"
check_modprobe_enabled "dummy2"
check_modprobe_num 2
