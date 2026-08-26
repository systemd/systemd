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
    local root first second third

    root="$(mktemp -d)"
    trap "root_cleanup $root" RETURN
    root_mock "$root"

    # Initialize the machine ID the regular way
    first="$(systemd-machine-id-setup --print --root "$root")"
    assert_neq "$first" ""

    # Without --force the existing ID is kept as-is
    assert_eq "$(systemd-machine-id-setup --print --root "$root")" "$first"

    # With --force a brand new ID is generated and written to disk
    second="$(systemd-machine-id-setup --print --force --root "$root")"
    assert_neq "$second" "$first"
    diff <(echo "$second") "$root/etc/machine-id"

    # ... and it is stable again once --force is not passed anymore
    assert_eq "$(systemd-machine-id-setup --print --root "$root")" "$second"

    # Each --force invocation yields yet another ID
    third="$(systemd-machine-id-setup --print --force --root "$root")"
    assert_neq "$third" "$second"
    diff <(echo "$third") "$root/etc/machine-id"
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

    # --force must not reuse it, as on a cloned system it would just carry over the old identity
    machine_id="$(systemd-machine-id-setup --print --force --root "$root")"
    assert_neq "$machine_id" "$dbus_id"
    diff <(echo "$machine_id") "$root/etc/machine-id"
}

testcase_force_uninitialized() {
    local root machine_id

    root="$(mktemp -d)"
    trap "root_cleanup $root" RETURN
    root_mock "$root"

    # An "uninitialized" marker is left alone by the regular code path...
    echo "uninitialized" >"$root/etc/machine-id"
    assert_eq "$(systemd-machine-id-setup --print --root "$root")" "uninitialized"

    # ... but --force replaces it with a real ID
    machine_id="$(systemd-machine-id-setup --print --force --root "$root")"
    assert_neq "$machine_id" "uninitialized"
    diff <(echo "$machine_id") "$root/etc/machine-id"
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
