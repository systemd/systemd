#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2064
set -eux
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh
# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

root_mock() {
    local root="${1:?}"

    mkdir -p "$root"
    # Put a tmpfs over the "root", so we're able to remount it as read-only
    # when needed
    mount -t tmpfs tmpfs "$root"
    mkdir "$root/etc" "$root/run"
}

root_cleanup() {
    local root="${1:?}"

    umount --recursive "$root"
    rm -fr "$root"
}

testcase_sanity() {
    systemd-machine-id-setup
    systemd-machine-id-setup --help
    systemd-machine-id-setup --version
    systemd-machine-id-setup --print
    systemd-machine-id-setup --root= --print
    systemd-machine-id-setup --root=/ --print

    (! systemd-machine-id-setup "")
    (! systemd-machine-id-setup --foo)
    # --commit and --force are mutually exclusive
    (! systemd-machine-id-setup --commit --force)
}

testcase_invalid() {
    local root machine_id

    root="$(mktemp -d)"
    trap "root_cleanup $root" RETURN
    root_mock "$root"

    systemd-machine-id-setup --print --root "$root"
    echo abc >>"$root/etc/machine-id"
    machine_id="$(systemd-machine-id-setup --print --root "$root")"
    diff <(echo "$machine_id") "$root/etc/machine-id"
}

testcase_force() {
    local root first second third fourth

    root="$(mktemp -d)"
    trap "root_cleanup $root" RETURN
    root_mock "$root"

    # Initialize the machine ID the regular way
    first="$(systemd-machine-id-setup --print --root "$root")"
    assert_neq "$first" ""

    # Without --force the existing ID is kept as-is
    assert_eq "$(systemd-machine-id-setup --print --root "$root")" "$first"

    # With --force a brand new ID is generated and written to disk, persistently:
    # nothing may be left behind in /run, that's the transient code path
    second="$(systemd-machine-id-setup --print --force --root "$root")"
    assert_neq "$second" "$first"
    diff <(echo "$second") "$root/etc/machine-id"
    test ! -e "$root/run/machine-id"

    # ... and it is stable again once --force is not passed anymore
    assert_eq "$(systemd-machine-id-setup --print --root "$root")" "$second"

    # Each --force invocation yields yet another ID
    third="$(systemd-machine-id-setup --print --force --root "$root")"
    assert_neq "$third" "$second"
    diff <(echo "$third") "$root/etc/machine-id"
    test ! -e "$root/run/machine-id"

    # A /run/machine-id left over from an earlier transient boot (machine_id_commit() does not
    # remove it) must not keep the replaced ID around, as it takes precedence on the next
    # initialization
    echo "$third" >"$root/run/machine-id"
    fourth="$(systemd-machine-id-setup --print --force --root "$root")"
    assert_neq "$fourth" "$third"
    diff <(echo "$fourth") "$root/etc/machine-id"
    diff <(echo "$fourth") "$root/run/machine-id"
}

testcase_force_readonly() {
    local root first

    root="$(mktemp -d)"
    trap "root_cleanup $root" RETURN
    root_mock "$root"

    first="$(systemd-machine-id-setup --print --root "$root")"
    assert_neq "$first" ""

    mount -o remount,ro "$root"
    mount -t tmpfs tmpfs "$root/run"

    # --force is about assigning a *persistent* identity, hence it must fail instead of
    # quietly falling back to a transient ID that is gone again on the next boot
    (! systemd-machine-id-setup --print --force --root "$root")
    test ! -e "$root/run/machine-id"

    mount -o remount,rw "$root"

    # ... and the ID that was in place is untouched
    assert_eq "$(systemd-machine-id-setup --print --root "$root")" "$first"
}

testcase_force_transient() {
    local root transient_id out

    root="$(mktemp -d)"
    trap "root_cleanup $root" RETURN
    root_mock "$root"

    systemd-machine-id-setup --print --root "$root"
    echo abc >>"$root/etc/machine-id"
    mount -o remount,ro "$root"
    mount -t tmpfs tmpfs "$root/run"

    # Install a transient ID over /etc/machine-id, the way PID 1 does on a read-only /etc
    transient_id="$(systemd-machine-id-setup --print --root "$root")"
    assert_neq "$transient_id" ""

    # --force must refuse rather than write through the overmount: that would clobber the ID
    # the system is actively using while persisting nothing. Pin the message: the read-only
    # remount makes the !writable guard fire too, so a plain non-zero exit would still pass
    # if the mount point guard were removed
    out="$(! systemd-machine-id-setup --print --force --root "$root" 2>&1)"
    assert_in "is a mount point" "$out"
    diff <(echo "$transient_id") "$root/run/machine-id"
}

testcase_force_volatile_etc() {
    local tmp out

    # The "/etc/ is on a temporary file system" refusal only applies to the host, i.e. without
    # --root=, so exercise it in a private mount namespace to keep the real /etc out of it.
    # Create the directory out here: inside the namespace it is a mount point and cannot be
    # removed, so it would be leaked behind.
    tmp="$(mktemp -d)"
    trap "rm -fr $tmp" RETURN

    # shellcheck disable=SC2016 # $1 is expanded by the inner shell, not this one
    # util.sh is not sourced inside the namespace, so assert out here on the captured output
    out="$(unshare --mount --propagation private bash -eux -c '
        mount -t tmpfs tmpfs "$1"
        systemd-id128 new >"$1/machine-id"
        mount --bind "$1" /etc

        # /etc/machine-id is a plain, writable file that is not a mount point here — it just
        # is not persistent, so --force must refuse rather than write an ID that is gone on
        # the next boot
        (! systemd-machine-id-setup --print --force)
    ' bash "$tmp" 2>&1)"
    assert_in "temporary file system" "$out"

    # Same with no /etc/machine-id at all: the tool creates one itself before the guard fires,
    # and must remove it again rather than leaving an empty file a later run would misread as
    # a deliberately emptied one
    # shellcheck disable=SC2016 # $1 is expanded by the inner shell, not this one
    out="$(unshare --mount --propagation private bash -eux -c '
        mount -t tmpfs tmpfs "$1"
        mount --bind "$1" /etc

        (! systemd-machine-id-setup --print --force)
        test ! -e /etc/machine-id
    ' bash "$tmp" 2>&1)"
    assert_in "temporary file system" "$out"
}

testcase_force_symlink() {
    local root target first second

    root="$(mktemp -d)"
    trap "root_cleanup $root" RETURN
    root_mock "$root"

    # /etc/machine-id pointing at a persistent location elsewhere: the guards and the write
    # all operate on the chase()d target, so make sure the symlink survives and the target
    # is what gets rewritten
    target="$root/persist/etc/machine-id"
    mkdir -p "$root/persist/etc"
    # the target has to exist: a dangling /etc/machine-id symlink is not a supported shape,
    # machine_id_setup() bails out on it, same as in testcase_transient_symlink
    echo abc >"$target"
    ln -s /persist/etc/machine-id "$root/etc/machine-id"

    first="$(systemd-machine-id-setup --print --root "$root")"
    assert_neq "$first" ""
    diff <(echo "$first") "$target"

    second="$(systemd-machine-id-setup --print --force --root "$root")"
    assert_neq "$second" "$first"
    diff <(echo "$second") "$target"

    # the symlink must still be a symlink, i.e. no regular file appeared in its place
    test -L "$root/etc/machine-id"
    test ! -e "$root/run/machine-id"
}

testcase_force_ignores_other_sources() {
    local root dbus_id machine_id

    root="$(mktemp -d)"
    trap "root_cleanup $root" RETURN
    root_mock "$root"

    # Set up a D-Bus machine ID, which is normally picked up when /etc/machine-id is empty
    dbus_id="$(systemd-id128 new)"
    mkdir -p "$root/var/lib/dbus"
    echo "$dbus_id" >"$root/var/lib/dbus/machine-id"

    machine_id="$(systemd-machine-id-setup --print --root "$root")"
    assert_eq "$machine_id" "$dbus_id"

    # --force must not reuse it, as on a cloned system it would just carry over the old identity...
    machine_id="$(systemd-machine-id-setup --print --force --root "$root")"
    assert_neq "$machine_id" "$dbus_id"
    diff <(echo "$machine_id") "$root/etc/machine-id"

    # ... and it must not leave the old one behind there either, as acquire_machine_id() would
    # hand it back on the next initialization
    diff <(echo "$machine_id") "$root/var/lib/dbus/machine-id"

    # A symlink there is left alone. Point it at a distinguishable target rather than at
    # /etc/machine-id: following it would rewrite byte-identical content there, so the case
    # could not tell whether CHASE_NOFOLLOW is still in effect
    rm -f "$root/var/lib/dbus/machine-id"
    echo "$dbus_id" >"$root/var/lib/dbus/other-id"
    ln -s /var/lib/dbus/other-id "$root/var/lib/dbus/machine-id"
    machine_id="$(systemd-machine-id-setup --print --force --root "$root")"
    test -L "$root/var/lib/dbus/machine-id"
    diff <(echo "$dbus_id") "$root/var/lib/dbus/other-id"
    diff <(echo "$machine_id") "$root/etc/machine-id"

    # Same for /run/machine-id: the -ELOOP skip must not follow it either. Capture the output:
    # a confirmed symlink stays at debug level, so no warning may appear
    ln -s /var/lib/dbus/other-id "$root/run/machine-id"
    out="$(systemd-machine-id-setup --print --force --root "$root" 2>&1)"
    machine_id="$(tail -n1 <<<"$out")"
    test -L "$root/run/machine-id"
    diff <(echo "$dbus_id") "$root/var/lib/dbus/other-id"
    assert_not_in "Not updating stale machine ID" "$out"
    diff <(echo "$machine_id") "$root/etc/machine-id"
}

testcase_force_stale_copy_loop() {
    local root out machine_id

    root="$(mktemp -d)"
    trap "root_cleanup $root" RETURN
    root_mock "$root"

    systemd-machine-id-setup --print --root "$root" >/dev/null

    # An intermediate symlink loop also makes chase() return -ELOOP, but unlike a final-component
    # symlink it is not something we skip on purpose, so it must surface as a warning rather than
    # be mistaken for the intended skip
    mkdir -p "$root/var/lib"
    ln -s dbus2 "$root/var/lib/dbus"
    ln -s dbus "$root/var/lib/dbus2"

    out="$(systemd-machine-id-setup --print --force --root "$root" 2>&1)"
    machine_id="$(tail -n1 <<<"$out")"
    assert_in "Not updating stale machine ID" "$out"
    diff <(echo "$machine_id") "$root/etc/machine-id"
}

testcase_force_stale_copy_failure() {
    local root out machine_id

    root="$(mktemp -d)"
    trap "root_cleanup $root" RETURN
    root_mock "$root"

    systemd-machine-id-setup --print --root "$root" >/dev/null

    # A stale copy we cannot write is not fatal — --force still assigns the new identity — but it
    # must not be swallowed at debug level either, or a half-reprovisioned clone looks complete
    mkdir -p "$root/var/lib/dbus/machine-id"

    out="$(systemd-machine-id-setup --print --force --root "$root" 2>&1)"
    machine_id="$(tail -n1 <<<"$out")"
    assert_in "Not updating stale machine ID" "$out"
    diff <(echo "$machine_id") "$root/etc/machine-id"
    test -d "$root/var/lib/dbus/machine-id"
}

testcase_force_uninitialized() {
    local root machine_id out

    root="$(mktemp -d)"
    trap "root_cleanup $root" RETURN
    root_mock "$root"

    # An "uninitialized" marker doubles as the first boot flag and carries no identity that
    # could have been duplicated by cloning, hence it is left alone — with --force as well
    echo "uninitialized" >"$root/etc/machine-id"
    assert_eq "$(systemd-machine-id-setup --print --root "$root")" "uninitialized"

    machine_id="$(systemd-machine-id-setup --print --force --root "$root")"
    assert_eq "$machine_id" "uninitialized"
    diff <(echo "uninitialized") "$root/etc/machine-id"

    # ... and it says so, so that --force is not a silent no-op. Pin the message and the --root=
    # qualifier: without them nothing here would notice the notice going away
    out="$(systemd-machine-id-setup --force --root "$root" 2>&1)"
    assert_in "leaving it as it is" "$out"
    assert_in "systemd-firstboot --force --root=$root --setup-machine-id" "$out"
}

testcase_transient() {
    local root transient_id committed_id

    root="$(mktemp -d)"
    trap "root_cleanup $root" RETURN
    root_mock "$root"

    systemd-machine-id-setup --print --root "$root"
    echo abc >>"$root/etc/machine-id"
    mount -o remount,ro "$root"
    mount -t tmpfs tmpfs "$root/run"
    transient_id="$(systemd-machine-id-setup --print --root "$root")"
    mount -o remount,rw "$root"
    committed_id="$(systemd-machine-id-setup --print --commit --root "$root")"
    [[ "$transient_id" == "$committed_id" ]]
    diff "$root/etc/machine-id" "$root/run/machine-id"
}

testcase_transient_symlink() {
    local root transient_id committed_id

    root="$(mktemp -d)"
    trap "root_cleanup $root" RETURN
    root_mock "$root"

    mkdir -p "$root/persist/etc"
    echo abc >>"$root/persist/etc/machine-id"
    ln -s /persist/etc/machine-id "$root/etc/machine-id"
    mount -o remount,ro "$root"
    mount -t tmpfs tmpfs "$root/run"
    transient_id="$(systemd-machine-id-setup --print --root "$root")"
    mountpoint "$root/persist/etc/machine-id"
    mount -o remount,rw "$root"
    committed_id="$(systemd-machine-id-setup --print --commit --root "$root")"
    [[ "$transient_id" == "$committed_id" ]]
    (! mountpoint "$root/persist/etc/machine-id")
    diff "$root/persist/etc/machine-id" "$root/run/machine-id"
}

# Check if we correctly processed the invalid machine ID we set up in the respective
# test.sh file
systemctl --state=failed --no-legend --no-pager | tee /failed
test ! -s /failed

run_testcases
