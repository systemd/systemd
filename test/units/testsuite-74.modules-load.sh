#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

MODULES_LOAD_BIN="/usr/lib/systemd/systemd-modules-load"
CONFIG_FILE="/run/modules-load.d/99-test.conf"

at_exit() {
    set +e
    rm -rfv "${CONFIG_FILE:?}" /tmp/cmdline
    mountpoint -q /proc/cmdline && umount /proc/cmdline
}

trap at_exit EXIT

if systemd-detect-virt -cq; then
    echo "Running in a container, skipping the systemd-modules-load test..."
    exit 0
fi

# Check if we have required kernel modules
modprobe --all --resolve-alias loop dummy

mkdir -p /run/modules-load.d/

"$MODULES_LOAD_BIN"
"$MODULES_LOAD_BIN" --help
"$MODULES_LOAD_BIN" --version

# Explicit config file
modprobe -v --all --remove loop dummy
printf "loop\ndummy" >"$CONFIG_FILE"
"$MODULES_LOAD_BIN" "$CONFIG_FILE" |& tee /tmp/out.log
grep -E "Inserted module .*loop" /tmp/out.log
grep -E "Inserted module .*dummy" /tmp/out.log

# Implicit config file
modprobe -v --all --remove loop dummy
printf "loop\ndummy" >"$CONFIG_FILE"
"$MODULES_LOAD_BIN" |& tee /tmp/out.log
grep -E "Inserted module .*loop" /tmp/out.log
grep -E "Inserted module .*dummy" /tmp/out.log

# Valid & invalid data mixed together
modprobe -v --all --remove loop dummy
cat >"$CONFIG_FILE" <<EOF

loop
loop
loop
    loop
dummy
    \\n\n\n\\\\\\
 
loo!@@123##2455
# This is a comment
$(printf "%.0sx" {0..4096})
dummy
loop
foo-bar-baz
1
"
'
EOF
"$MODULES_LOAD_BIN" |& tee /tmp/out.log
grep -E "^Inserted module .*loop" /tmp/out.log
grep -E "^Inserted module .*dummy" /tmp/out.log
grep -E "^Failed to find module .*foo-bar-baz" /tmp/out.log
(! grep -E "This is a comment" /tmp/out.log)
# Each module should be loaded only once, even if specified multiple times
[[ "$(grep -Ec "^Inserted module" /tmp/out.log)" -eq 2 ]]
[[ "$(grep -Ec "^Failed to find module" /tmp/out.log)" -eq 7 ]]

# Command line arguments
modprobe -v --all --remove loop dummy
# Make sure we have no config files left over that might interfere with
# following tests
rm -fv "$CONFIG_FILE"
[[ -z "$(systemd-analyze cat-config modules-load.d)" ]]
# Copy over the existing kernel cmdline, so we can amend it, and then overmount
# the original one with the amended cmdline
cp -fv /proc/cmdline /tmp/cmdline
sed -i 's/$/ modules_load= modules_load=, modules_load=foo-bar-baz,dummy modules_load=loop,loop,loop/' /tmp/cmdline
mount -v --bind /tmp/cmdline /proc/cmdline
"$MODULES_LOAD_BIN" |& tee /tmp/out.log
grep -E "^Inserted module .*loop" /tmp/out.log
grep -E "^Inserted module .*dummy" /tmp/out.log
grep -E "^Failed to find module .*foo-bar-baz" /tmp/out.log
# Each module should be loaded only once, even if specified multiple times
[[ "$(grep -Ec "^Inserted module" /tmp/out.log)" -eq 2 ]]
umount -v /proc/cmdline

(! "$MODULES_LOAD_BIN" --nope)
(! "$MODULES_LOAD_BIN" /foo/bar/baz)
