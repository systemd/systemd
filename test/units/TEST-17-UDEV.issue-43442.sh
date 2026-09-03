#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Issue: https://github.com/systemd/systemd/issues/43442
#
# A daemon-reload must not resurrect a .swap unit whose device link has disappeared.
#
# systemd creates one .swap unit per udev device link of every device listed in /proc/swaps. When such a
# device link goes away (e.g. because it is not unique and udev repoints it at another partition) while the
# swap itself stays on, the unit named after the link is left behind: the next daemon-reload drops all units
# and rebuilds them, the enumeration from /proc/swaps no longer knows the link, and the unit is only
# resurrected by the deserialization, i.e. by name, with no fragment on disk. That used to leave it
#
#     LoadState=not-found, ActiveState=active, What=

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

LOOPDEV=""
UDEV_RULE=/run/udev/rules.d/99-testsuite-orphan-swap.rules
DEVLINK=/dev/testsuite-orphan-swap
SWAP_UNIT="$(systemd-escape --path --suffix=swap "$DEVLINK")"
FRAGMENT="/run/systemd/system/$SWAP_UNIT"
# Not /tmp/, that's a tmpfs here: swapping onto a loop device backed by memory that can itself be swapped
# out is a deadlock waiting to happen.
WORKDIR="$(mktemp -d -p /var/tmp)"

at_exit() (
    set +e

    [[ -n "$LOOPDEV" ]] && swapoff "$LOOPDEV"

    rm -f "$FRAGMENT" "$UDEV_RULE"
    udevadm control --reload

    if [[ -z "$LOOPDEV" ]]; then
        rm -rf "$WORKDIR"
    else
        timeout 30 udevadm trigger --settle --action change "$LOOPDEV"

        # Neither detach the loop device nor unlink its backing file while the swap is still on: the
        # /proc/swaps entry outlives both, naming a device node that is gone, and leaks into the subtests
        # that follow in the same boot.
        if swapon --show=NAME --noheadings | grep -x "$LOOPDEV" >/dev/null; then
            echo "$LOOPDEV is still swapped on, leaving it and $WORKDIR behind" >&2
        else
            losetup -d "$LOOPDEV"
            rm -rf "$WORKDIR"
        fi
    fi
)

trap at_exit EXIT

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
timeout 30 udevadm trigger --settle --action change "$LOOPDEV"
udevadm wait --timeout=30 --settle "$DEVLINK"

LOOP_SWAP_UNIT="$(systemd-escape --path --suffix=swap "$LOOPDEV")"

swapon --fixpgsz "$LOOPDEV"
swapon --show

# shellcheck disable=SC2016
timeout 30 bash -c 'until systemctl -q is-active "$1"; do sleep .5; done' bash "$SWAP_UNIT"
assert_eq "$(systemctl show -P LoadState "$SWAP_UNIT")" "loaded"
assert_eq "$(systemctl show -P What "$SWAP_UNIT")" "$DEVLINK"

# Now drop the device link again, without touching the swap itself, and reload. /proc/swaps still lists the
# loop device, but nothing knows the unit name anymore.
rm -f "$UDEV_RULE"
udevadm control --reload
timeout 30 udevadm trigger --settle --action change "$LOOPDEV"
udevadm wait --timeout=30 --settle --removed "$DEVLINK"
assert_not_in "${DEVLINK#/dev/}" "$(udevadm info --query=symlink "$LOOPDEV")"

systemctl daemon-reload

# The unit is orphaned now: /proc/swaps doesn't know it, and there's no fragment on disk either. It must
# not have been brought back as active
systemctl show "$SWAP_UNIT" --property=Id,LoadState,ActiveState,SubState,What
assert_eq "$(systemctl show -P ActiveState "$SWAP_UNIT")" "inactive"

# The unit named after the loop device itself is backed by /proc/swaps and must have survived, i.e. the
# guard must not be over-broad.
assert_rc 0 systemctl -q is-active "$LOOP_SWAP_UNIT"

# Now the same thing once more, except that this time the unit has a fragment on disk. Being loadable is
# the other half of what the guard keys on, so this one has to survive losing its device link. Note the
# fragment must be named after What=, swap_verify() insists on it.
cat >"$FRAGMENT" <<EOF
[Swap]
What=$DEVLINK
EOF
cat >"$UDEV_RULE" <<EOF
SUBSYSTEM=="block", KERNEL=="${LOOPDEV#/dev/}", SYMLINK+="${DEVLINK#/dev/}"
EOF
udevadm control --reload
timeout 30 udevadm trigger --settle --action change "$LOOPDEV"
udevadm wait --timeout=30 --settle "$DEVLINK"

systemctl daemon-reload
assert_eq "$(systemctl show -P LoadState "$SWAP_UNIT")" "loaded"
assert_rc 0 systemctl -q is-active "$SWAP_UNIT"

rm -f "$UDEV_RULE"
udevadm control --reload
timeout 30 udevadm trigger --settle --action change "$LOOPDEV"
udevadm wait --timeout=30 --settle --removed "$DEVLINK"

systemctl daemon-reload
systemctl show "$SWAP_UNIT" --property=Id,LoadState,ActiveState,SubState,What
assert_eq "$(systemctl show -P LoadState "$SWAP_UNIT")" "loaded"
assert_rc 0 systemctl -q is-active "$SWAP_UNIT"

# The real swap is untouched
swapon --show=NAME --noheadings | grep -x "$LOOPDEV" >/dev/null
