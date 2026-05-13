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

# Check if we correctly processed the invalid machine ID we set up in the respective
# test.sh file
systemctl --state=failed --no-legend --no-pager | tee /failed
test ! -s /failed

run_testcases
