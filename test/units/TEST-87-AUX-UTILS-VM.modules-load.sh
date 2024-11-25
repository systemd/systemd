#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

MODULES_LOAD_BIN="/usr/lib/systemd/systemd-modules-load"
CONFIG_FILE="/run/modules-load.d/99-test.conf"

at_exit() {
    rm -rfv "${CONFIG_FILE:?}"
}

(! systemd-detect-virt -cq)

trap at_exit EXIT

ORIG_MODULES_LOAD_CONFIG="$(systemd-analyze cat-config modules-load.d)"

# Check if we have required kernel modules
modprobe --all --resolve-alias dummy

mkdir -p /run/modules-load.d/

"$MODULES_LOAD_BIN"
"$MODULES_LOAD_BIN" --help
"$MODULES_LOAD_BIN" --version

# Explicit config file
modprobe -v --all --remove dummy
printf "dummy" >"$CONFIG_FILE"
"$MODULES_LOAD_BIN" "$CONFIG_FILE" |& tee /tmp/out.log
grep -E "Inserted module .*dummy" /tmp/out.log

# Implicit config file
modprobe -v --all --remove dummy
printf "dummy" >"$CONFIG_FILE"
"$MODULES_LOAD_BIN" |& tee /tmp/out.log
grep -E "Inserted module .*dummy" /tmp/out.log

# Valid & invalid data mixed together
modprobe -v --all --remove dummy
cat >"$CONFIG_FILE" <<EOF

dummy
dummy
dummy
    dummy
dummy
    \\n\n\n\\\\\\

dumm!@@123##2455
# This is a comment
$(printf "%.0sx" {0..4096})
dummy
dummy
foo-bar-baz
1
"
'
EOF
"$MODULES_LOAD_BIN" |& tee /tmp/out.log
grep -E "^Inserted module .*dummy" /tmp/out.log
grep -E "^Failed to find module .*foo-bar-baz" /tmp/out.log
(! grep -E "This is a comment" /tmp/out.log)
# Each module should be loaded only once, even if specified multiple times
[[ "$(grep -Ec "^Inserted module" /tmp/out.log)" -eq 1 ]]
[[ "$(grep -Ec "^Failed to find module" /tmp/out.log)" -eq 7 ]]

# Command line arguments
modprobe -v --all --remove dummy
# Make sure we have no config files left over that might interfere with
# following tests
rm -fv "$CONFIG_FILE"
[[ "$ORIG_MODULES_LOAD_CONFIG" == "$(systemd-analyze cat-config modules-load.d)" ]]
CMDLINE="ro root= modules_load= modules_load=, / = modules_load=foo-bar-baz,dummy modules_load=dummy,dummy,dummy"
SYSTEMD_PROC_CMDLINE="$CMDLINE" "$MODULES_LOAD_BIN" |& tee /tmp/out.log
grep -E "^Inserted module .*dummy" /tmp/out.log
grep -E "^Failed to find module .*foo-bar-baz" /tmp/out.log
# Each module should be loaded only once, even if specified multiple times
[[ "$(grep -Ec "^Inserted module" /tmp/out.log)" -eq 1 ]]

(! "$MODULES_LOAD_BIN" --nope)
(! "$MODULES_LOAD_BIN" /foo/bar/baz)
