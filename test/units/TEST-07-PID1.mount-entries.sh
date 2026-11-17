#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# Tests for how mount entries on the same or nested paths override and merge with
# each other: explicitly configured mounts (TemporaryFileSystem=, BindPaths=,
# ReadOnlyPaths=, …) override the ones implied by the sandboxing options
# (ProtectHome=, ProtectSystem=, MountAPIVFS=, PrivateDevices=, PrivateNetwork=,
# …), and keep their own attributes rather than taking the implied ones.
# Entries below an inaccessible path are masked, attribute-only entries that
# conflict are merged with the more restrictive one winning, and entries on
# paths that do not exist are skipped if they may be ignored.

# Bind sources are put on the root file system, so that the file system type of
# the bind can be told apart from tmpfs and proc.
bind_source=/root/mount-entries-bind-source
proc_source=/root/mount-entries-proc-source
mkdir "$bind_source" "$proc_source"
echo marker >"$bind_source/marker"
echo marker >"$proc_source/marker"
cp /bin/true "$proc_source/true"
echo marker >/root/mount-entries-var-marker
mkdir /tmp/mount-entries-rw

cleanup() {
    rm -rf "$bind_source" "$proc_source" /root/mount-entries-var-marker /tmp/mount-entries-rw
}
trap cleanup EXIT

# In coverage builds ProtectSystem= and ProtectHome= are disabled via a drop-in
# that overrides the transient settings, hence the test cases that rely on them
# are skipped there.

# An explicitly configured tmpfs overrides the implied one from ProtectHome=tmpfs,
# and keeps its own attributes, i.e. it stays writable.
if [[ -z "${COVERAGE_BUILD_DIR:-}" ]]; then
    systemd-run --wait --pipe \
        -p ProtectHome=tmpfs \
        -p TemporaryFileSystem=/home \
        bash -xec '
            [[ "$(stat -fc %T /home)" == tmpfs ]]
            [[ -z "$(ls -A /home)" ]]
            test -w /home
        '

    # An explicitly configured bind overrides the inaccessible node from
    # ProtectHome=yes, and keeps its own attributes, i.e. it stays writable.
    systemd-run --wait --pipe \
        -p ProtectHome=yes \
        -p BindPaths="$bind_source:/home" \
        bash -xec '
            [[ "$(stat -fc %T /home)" != tmpfs ]]
            test -f /home/marker
            test -w /home
        '

    # An explicitly configured tmpfs overrides the read-only remount from
    # ProtectSystem=yes, and keeps its own attributes, i.e. it stays writable.
    systemd-run --wait --pipe \
        -p ProtectSystem=yes \
        -p TemporaryFileSystem=/boot \
        bash -xec '
            [[ "$(stat -fc %T /boot)" == tmpfs ]]
            [[ -z "$(ls -A /boot)" ]]
            test -w /boot
        '
fi

# An explicitly configured bind overrides the API VFS mount from MountAPIVFS=,
# and keeps its own attributes, i.e. it stays executable.
systemd-run --wait --pipe \
    -p MountAPIVFS=yes \
    -p BindPaths="$proc_source:/proc" \
    bash -xec '
        [[ "$(stat -fc %T /proc)" != proc ]]
        test -f /proc/marker
        /proc/true
    '

# An explicitly configured tmpfs overrides the private one from PrivateDevices=,
# and keeps its own attributes, i.e. it stays writable.
systemd-run --wait --pipe \
    -p PrivateDevices=yes \
    -p TemporaryFileSystem=/dev \
    bash -xec '
        [[ "$(stat -fc %T /dev)" == tmpfs ]]
        (! test -e /dev/null)
        test -w /dev
    '

# An explicitly configured tmpfs overrides the private one from PrivateNetwork=,
# and keeps its own attributes, i.e. it stays executable.
systemd-run --wait --pipe \
    -p PrivateNetwork=yes \
    -p TemporaryFileSystem=/sys \
    bash -xec '
        [[ "$(stat -fc %T /sys)" == tmpfs ]]
        (! test -e /sys/class)
        cp /bin/true /sys/
        /sys/true
    '

# If read-only and read-write are requested for the same path, the more
# restrictive one wins.
systemd-run --wait --pipe \
    -p ReadOnlyPaths=/tmp/mount-entries-rw \
    -p ReadWritePaths=/tmp/mount-entries-rw \
    bash -xec '(! test -w /tmp/mount-entries-rw)'

# An explicitly configured bind takes over the read-only attribute of an
# attribute-only entry on the same path.
systemd-run --wait --pipe \
    -p BindPaths="$bind_source:/mnt" \
    -p ReadOnlyPaths=/mnt \
    bash -xec '
        test -f /mnt/marker
        (! test -w /mnt)
    '

if [[ -z "${COVERAGE_BUILD_DIR:-}" ]]; then
    # Entries below an inaccessible path are masked, even explicitly configured
    # ones.
    systemd-run --wait --pipe \
        -p ProtectHome=yes \
        -p BindPaths="$bind_source:/home/sub" \
        bash -xec '(! test -e /home/sub)'

    # An optional bind whose source does not exist is skipped, and the inaccessible node
    # from ProtectHome=yes that it overrode is applied after all.
    touch /root/mount-entries-fallback-marker
    systemd-run --wait --pipe \
        -p ProtectHome=yes \
        -p BindPaths=-/nonexistent:/root \
        bash -xec '(! test -e /root/mount-entries-fallback-marker)'
    rm -f /root/mount-entries-fallback-marker

    # With RootDirectory= /run/ is a fresh tmpfs (as MountAPIVFS= is implied),
    # hence /run/user/ does not exist unless it is created. The inaccessible node
    # that ProtectHome=yes puts there, merged with the read-write carve-out that
    # ProtectSystem=strict puts on the same path, must be skipped instead of
    # failing the unit.
    systemd-run --wait --pipe \
        -p RootDirectory=/ \
        -p ProtectHome=yes \
        -p ProtectSystem=strict \
        bash -xec '
            [[ "$(stat -fc %T /run)" == tmpfs ]]
            (! test -e /run/user)
            (! test -w /etc)
        '

    # Same for DynamicUser=yes, which implies ProtectSystem=strict and
    # ProtectHome=read-only.
    systemd-run --wait --pipe \
        -p DynamicUser=yes \
        -p RootDirectory=/ \
        bash -xec '(! test -e /run/user)'
fi

# An explicitly configured inaccessible node wins over an explicitly configured
# bind on the same path.
systemd-run --wait --pipe \
    -p BindPaths="$bind_source:/mnt" \
    -p InaccessiblePaths=/mnt \
    bash -xec '(! test -e /mnt/marker)'

# The options of an explicitly configured tmpfs win over the ones of the implied
# /run/ tmpfs.
systemd-run --wait --pipe \
    -p RootDirectory=/ \
    -p "TemporaryFileSystem=/run:mode=0700" \
    bash -xec '[[ "$(stat -c %a /run)" == 700 ]]'

# Mounts on nested paths are applied in path order, hence a bind below a tmpfs
# is visible in the tmpfs.
systemd-run --wait --pipe \
    -p TemporaryFileSystem=/var \
    -p BindPaths=/root/mount-entries-var-marker:/var/marker \
    bash -xec '
        [[ "$(stat -fc %T /var)" == tmpfs ]]
        test -f /var/marker
    '
