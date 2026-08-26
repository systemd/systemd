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
    local root first content out

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

    # The same holds where there is no usable ID to replace: the fall-through arm must not
    # quietly install a transient overmount and exit 0 either
    for content in "" "abc"; do
        echo -n "$content" >"$root/etc/machine-id"
        mount -o remount,ro "$root"
        out="$(! systemd-machine-id-setup --print --force --root "$root" 2>&1)"
        assert_in "Refusing" "$out"
        test ! -e "$root/run/machine-id"
        mount -o remount,rw "$root"
    done
}

testcase_force_transient() {
    local root transient_id on_disk out

    root="$(mktemp -d)"
    trap "root_cleanup $root" RETURN
    root_mock "$root"

    systemd-machine-id-setup --print --root "$root"
    echo abc >>"$root/etc/machine-id"
    on_disk="$(cat "$root/etc/machine-id")"
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
    # every refusal happens before the truncation, so the ID in place must be untouched — both the
    # transient one and, underneath the overmount, the on-disk file --force would have written to
    diff <(echo "$transient_id") "$root/run/machine-id"
    umount "$root/etc/machine-id"
    diff <(echo "$on_disk") "$root/etc/machine-id"
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

        # contain the blast radius: if the guard ever regresses, --force succeeds and
        # update_stale_machine_ids(root=NULL) would otherwise rewrite the host copies. /var/lib
        # rather than /var/lib/dbus, as the latter need not exist and mkdir is not namespaced
        mount -t tmpfs tmpfs /run
        mount -t tmpfs tmpfs /var/lib

        # /etc/machine-id is a plain, writable file that is not a mount point here — it just
        # is not persistent, so --force must refuse rather than write an ID that is gone on
        # the next boot
        (! systemd-machine-id-setup --print --force)
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
    local root dbus_id machine_id out

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

testcase_force_fallthrough_skips_dbus() {
    local root dbus_id machine_id

    root="$(mktemp -d)"
    trap "root_cleanup $root" RETURN
    root_mock "$root"

    # On the shape machine-id(5) tells people to ship — an empty /etc/machine-id — --force falls
    # through to the regular initialization, but must not pick up the D-Bus copy there: that one is
    # by construction the identity being cloned, so every clone would end up sharing it
    dbus_id="$(systemd-id128 new)"
    mkdir -p "$root/var/lib/dbus"
    echo "$dbus_id" >"$root/var/lib/dbus/machine-id"
    : >"$root/etc/machine-id"

    machine_id="$(systemd-machine-id-setup --print --force --root "$root")"
    assert_neq "$machine_id" "$dbus_id"
    diff <(echo "$machine_id") "$root/etc/machine-id"

    # The stale-copy rewrite is keyed on the flag, not on which arm ran, so the D-Bus copy is
    # brought in line here too rather than being left holding the cloned identity
    diff <(echo "$machine_id") "$root/var/lib/dbus/machine-id"

    # A corrupt ID is "no ID in place" too, and must behave the same
    echo "$dbus_id" >"$root/var/lib/dbus/machine-id"
    echo abc >"$root/etc/machine-id"
    machine_id="$(systemd-machine-id-setup --print --force --root "$root")"
    assert_neq "$machine_id" "$dbus_id"
    diff <(echo "$machine_id") "$root/etc/machine-id"

    # Without --force the D-Bus copy is still honoured, as before
    echo "$dbus_id" >"$root/var/lib/dbus/machine-id"
    : >"$root/etc/machine-id"
    machine_id="$(systemd-machine-id-setup --print --root "$root")"
    assert_eq "$machine_id" "$dbus_id"
}

testcase_force_stale_copy_links() {
    local root first second out

    root="$(mktemp -d)"
    trap "root_cleanup $root" RETURN
    root_mock "$root"

    first="$(systemd-machine-id-setup --print --root "$root")"
    mkdir -p "$root/var/lib/dbus"

    # Hard-linked to /etc/machine-id, a shape that occurs in the wild: CHASE_NOFOLLOW does not catch
    # that, so the loop must recognise the inode it just wrote and leave it alone rather than
    # truncating the primary file. The end state is the same either way — same inode, same new ID —
    # so the truncation window is only observable in the log
    ln "$root/etc/machine-id" "$root/var/lib/dbus/machine-id"
    out="$(SYSTEMD_LOG_LEVEL=debug systemd-machine-id-setup --print --force --root "$root" 2>&1)"
    second="$(tail -n1 <<<"$out")"
    assert_neq "$second" "$first"
    assert_in "is the file we just wrote, skipping" "$out"
    assert_not_in "Failed to check whether" "$out"
    test -s "$root/etc/machine-id"
    diff <(echo "$second") "$root/etc/machine-id"
    diff <(echo "$second") "$root/var/lib/dbus/machine-id"

    # Hard-linked to something *else*: the inode has a second name we were never pointed at, and
    # chase() does not look at st_nlink, so rewriting it would destroy that other file
    rm -f "$root/var/lib/dbus/machine-id"
    first="$second"
    echo "$first" >"$root/var/lib/dbus/other-file"
    ln "$root/var/lib/dbus/other-file" "$root/var/lib/dbus/machine-id"

    out="$(systemd-machine-id-setup --print --force --root "$root" 2>&1)"
    second="$(tail -n1 <<<"$out")"
    assert_neq "$second" "$first"
    assert_in "has more than one link" "$out"

    # neither name was touched
    diff <(echo "$first") "$root/var/lib/dbus/other-file"
    diff <(echo "$first") "$root/var/lib/dbus/machine-id"
    diff <(echo "$second") "$root/etc/machine-id"
}

testcase_force_stale_copy_failure() {
    local root out machine_id

    root="$(mktemp -d)"
    trap "root_cleanup $root" RETURN
    root_mock "$root"

    systemd-machine-id-setup --print --root "$root" >/dev/null

    # A stale copy we cannot write is not fatal — --force still assigns the new identity — but it
    # must not be swallowed at debug level either, or a half-reprovisioned clone looks complete.
    # Two shapes reach that: a non-regular inode, and an intermediate symlink loop, which yields
    # -ELOOP without being the final-component symlink we skip on purpose
    mkdir -p "$root/var/lib/dbus/machine-id"
    out="$(systemd-machine-id-setup --print --force --root "$root" 2>&1)"
    machine_id="$(tail -n1 <<<"$out")"
    assert_in "Not updating stale machine ID" "$out"
    diff <(echo "$machine_id") "$root/etc/machine-id"
    test -d "$root/var/lib/dbus/machine-id"

    rm -fr "$root/var/lib/dbus"
    ln -s dbus2 "$root/var/lib/dbus"
    ln -s dbus "$root/var/lib/dbus2"
    out="$(systemd-machine-id-setup --print --force --root "$root" 2>&1)"
    machine_id="$(tail -n1 <<<"$out")"
    assert_in "Not updating stale machine ID" "$out"
    diff <(echo "$machine_id") "$root/etc/machine-id"
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
    assert_in "systemd-firstboot --root=$root --force --setup-machine-id" "$out"
    # the caveat matters more than the command: firstboot bypasses every check --force makes
    assert_in "stale copies" "$out"

    # The hint is offered for copy-paste into a root shell, so the path has to be quoted. A
    # mktemp -d path has nothing worth quoting, so use one with whitespace: without the quoting
    # the hint would truncate at the space and name a different tree
    mkdir -p "$root/with space/etc"
    echo "uninitialized" >"$root/with space/etc/machine-id"
    out="$(systemd-machine-id-setup --force --root "$root/with space" 2>&1)"
    assert_in "--root=" "$out"
    assert_not_in "--root=$root/with space " "$out"

    # Note: the --image= shape of that hint is not covered here, as it would need a real disk
    # image carrying an "uninitialized" machine ID. Collapsing the --image= arm in
    # machine-id-setup-main.c back to arg_root would not be caught by this suite.
}

testcase_force_cmdline_machine_id() {
    local tmp out

    # This guard only applies to the host, so it has to run without --root=. Do it in a private mount
    # namespace with its own /etc — and its own /run and /var/lib/dbus, since the successful runs below
    # reach update_stale_machine_ids(root=NULL), which would otherwise rewrite the real ones.
    #
    # The fixture must not sit on a tmpfs: the temporary-file-system guard runs right after this one, so
    # the invocations that are expected to succeed would be refused for the wrong reason. /tmp is a tmpfs
    # in the test image, /var/tmp is not.
    tmp="$(mktemp --tmpdir=/var/tmp -d)"
    trap "rm -fr $tmp" RETURN
    assert_neq "$(stat -f -c %T "$tmp")" "tmpfs"

    # The refusal keys on the *value*: only something parsing as a non-null ID actually outranks
    # /etc/machine-id on the next boot. A valueless key is discarded by PID 1, and =firmware
    # leaves the file itself authoritative, so neither of those may refuse.
    # shellcheck disable=SC2016 # expanded by the inner shell, not this one
    out="$(unshare --mount --propagation private bash -eux -c '
        mkdir -p "$1/etc" "$1/run" "$1/dbus"
        mount --bind "$1/etc" /etc
        mount --bind "$1/run" /run
        # /var/lib exists everywhere; /var/lib/dbus may not, and mkdir is not namespaced, so
        # mount the fixture over /var/lib and recreate dbus/ inside it instead of on the host
        mount --bind "$1" /var/lib
        mkdir -p /var/lib/dbus

        systemd-id128 new >/etc/machine-id
        first="$(cat /etc/machine-id)"
        echo "$first" >/var/lib/dbus/machine-id

        cmdline="systemd.machine_id=$(systemd-id128 new)"
        SYSTEMD_PROC_CMDLINE="$cmdline" sh -c "! systemd-machine-id-setup --print --force"

        # ... and the ID in place is untouched by that refusal
        test "$(cat /etc/machine-id)" = "$first"
        test "$(cat /var/lib/dbus/machine-id)" = "$first"

        # The guard is host-only: under --root= the same command line must not refuse
        mkdir -p "$1/tree/etc"
        systemd-id128 new >"$1/tree/etc/machine-id"
        SYSTEMD_PROC_CMDLINE="$cmdline" systemd-machine-id-setup --print --force --root "$1/tree"

        # ... while these two must go through and actually replace the ID, stale copies included
        old="$(cat /etc/machine-id)"
        SYSTEMD_PROC_CMDLINE="systemd.machine_id=firmware" systemd-machine-id-setup --print --force
        test "$(cat /etc/machine-id)" != "$old"
        test "$(cat /var/lib/dbus/machine-id)" = "$(cat /etc/machine-id)"

        old="$(cat /etc/machine-id)"
        SYSTEMD_PROC_CMDLINE="systemd.machine_id" systemd-machine-id-setup --print --force
        test "$(cat /etc/machine-id)" != "$old"
        test "$(cat /var/lib/dbus/machine-id)" = "$(cat /etc/machine-id)"
    ' bash "$tmp" 2>&1)"
    assert_in "takes precedence" "$out"
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
