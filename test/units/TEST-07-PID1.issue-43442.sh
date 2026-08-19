#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

# Issue: https://github.com/systemd/systemd/issues/43442
#
# Stopping an active .swap unit whose device link has disappeared must not take PID 1 down.
#
# systemd creates one .swap unit per udev device link of every device listed in /proc/swaps. When such a
# device link goes away (e.g. because it is not unique and udev repoints it at another partition) while the
# swap itself stays on, the unit named after the link is left behind: the next daemon-reload drops all units
# and rebuilds them, the enumeration from /proc/swaps no longer knows the link, and the unit is only
# resurrected by the deserialization, i.e. by name, with no fragment on disk. That leaves it
#
#     LoadState=not-found, ActiveState=active, What=
#
# because swap_load() only calls swap_add_extras() -- and hence unit_patch_contexts() -- for units that
# either loaded a fragment or are backed by /proc/swaps. unit_stop() intentionally does not refuse unloaded
# units (one must be able to stop a unit whose fragment vanished), so the shutdown transaction runs
# swap_stop() -> swap_spawn() on a unit whose ExecContext was never patched, and the assertion on
# PrivateVarTmp= in exec_context_serialize() aborts PID 1. The crash handler then freezes PID 1, so the
# machine never reboots and has to be power cycled.

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

if systemd-detect-virt --container --quiet; then
    echo "Running in a container, skipping the test..."
    exit 0
fi

LOOPDEV=""
UDEV_RULE=/run/udev/rules.d/99-testsuite-orphan-swap.rules
DEVLINK=/dev/testsuite-orphan-swap
# Not /tmp/, that's a tmpfs here: swapping onto a loop device backed by memory that can
# itself be swapped out is a deadlock waiting to happen.
WORKDIR="$(mktemp -d -p /var/tmp)"

at_exit() (
    set +e

    [[ -n "$LOOPDEV" ]] && swapoff "$LOOPDEV"
    [[ -n "$LOOPDEV" ]] && losetup -d "$LOOPDEV"
    rm -f "$UDEV_RULE"
    udevadm control --reload
    rm -rf "$WORKDIR"
)

trap at_exit EXIT

# Make sure PID 1 is still there and still talks to us. If it hit the assertion it is frozen in
# freeze() and every D-Bus round trip runs into the method call timeout instead.
assert_pid1_alive() {
    assert_rc 0 timeout 60 systemctl show --property=Version --value
    assert_rc 0 timeout 60 systemd-run --wait --pipe --quiet true
    (! journalctl -b --grep "Freezing execution" _PID=1)
}

truncate -s 64M "$WORKDIR"/swap.img
LOOPDEV="$(losetup --show --find "$WORKDIR"/swap.img)"
mkswap "$LOOPDEV"

# Give the loop device an extra device link, so that systemd creates a second .swap unit named after it
# once the swap is on.
mkdir -p /run/udev/rules.d
cat >"$UDEV_RULE" <<EOF
SUBSYSTEM=="block", KERNEL=="${LOOPDEV#/dev/}", SYMLINK+="${DEVLINK#/dev/}"
EOF
udevadm control --reload
udevadm trigger --settle --action change "$LOOPDEV"
udevadm wait --timeout=30 --settle "$DEVLINK"

SWAP_UNIT="$(systemd-escape --path --suffix=swap "$DEVLINK")"

swapon --fixpgsz "$LOOPDEV"
swapon --show

timeout 30 bash -c "until [[ \"\$(systemctl show -P ActiveState '$SWAP_UNIT')\" == active ]]; do sleep .5; done"
assert_eq "$(systemctl show -P LoadState "$SWAP_UNIT")" "loaded"
assert_eq "$(systemctl show -P What "$SWAP_UNIT")" "$DEVLINK"

# Now drop the device link again, without touching the swap itself, and reload. /proc/swaps still lists the
# loop device, but nothing knows the unit name anymore.
rm -f "$UDEV_RULE"
udevadm control --reload
udevadm trigger --settle --action change "$LOOPDEV"
udevadm wait --timeout=30 --settle --removed "$DEVLINK"
assert_not_in "${DEVLINK#/dev/}" "$(udevadm info --query=symlink "$LOOPDEV")"

systemctl daemon-reload

# The unit is orphaned now. If these ever stop holding, the reproducer below is no longer reproducing
# anything and needs to be revisited.
systemctl show "$SWAP_UNIT" --property=Id,LoadState,ActiveState,SubState,What
assert_eq "$(systemctl show -P ActiveState "$SWAP_UNIT")" "active"
assert_eq "$(systemctl show -P What "$SWAP_UNIT")" ""

# This is what the shutdown transaction does, and what used to abort PID 1. The stop is allowed to fail
# (there is no device to hand to swapoff), it just has to fail without killing the manager.
timeout 60 systemctl stop "$SWAP_UNIT" || :

assert_pid1_alive

# ... and the job must have made progress, otherwise shutdown would hang here instead.
timeout 30 bash -c "until [[ \"\$(systemctl show -P ActiveState '$SWAP_UNIT')\" =~ ^(inactive|failed)\$ ]]; do sleep .5; done"

# The real swap is untouched, we never got a chance to swapoff anything.
assert_in "$LOOPDEV" "$(swapon --show=NAME --noheadings)"
