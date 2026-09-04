#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2235
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# Test unit configuration/state/cache/log/runtime data cleanup

export HOME=/root
export XDG_RUNTIME_DIR=/run/user/0

at_exit() {
    set +e

    systemctl --user stop test-execdir-flags.service test-execdir-colon.service
    rm -fr "$HOME"/.config/corge "$HOME"/.config/foo "$HOME"/.config/quux* "$HOME"/.local/state/bar "$HOME"/.local/state/foo \
           "$HOME"/.local/state/grault* "$HOME"/.local/state/private \
           "$HOME"/.local/state/waldo
}

trap at_exit EXIT

systemctl start user@0.service

( ! test -d "$HOME"/.local/state/foo)
( ! test -d "$HOME"/.config/foo)

systemd-run --user -p StateDirectory=foo --wait true

test -d "$HOME"/.local/state/foo
( ! test -L "$HOME"/.local/state/foo)
( ! test -d "$HOME"/.config/foo)

systemd-run --user -p StateDirectory=foo -p ConfigurationDirectory=foo --wait true

test -d "$HOME"/.local/state/foo
( ! test -L "$HOME"/.local/state/foo)
test -d "$HOME"/.config/foo

rmdir "$HOME"/.local/state/foo "$HOME"/.config/foo

systemd-run --user -p StateDirectory=foo -p ConfigurationDirectory=foo --wait true

test -d "$HOME"/.local/state/foo
( ! test -L "$HOME"/.local/state/foo)
test -d "$HOME"/.config/foo

rmdir "$HOME"/.local/state/foo "$HOME"/.config/foo

# Now trigger an update scenario by creating a config dir first
systemd-run --user -p ConfigurationDirectory=foo --wait true

( ! test -d "$HOME"/.local/state/foo)
test -d "$HOME"/.config/foo

# This will look like an update and result in a symlink
systemd-run --user -p StateDirectory=foo -p ConfigurationDirectory=foo --wait true

test -d "$HOME"/.local/state/foo
test -L "$HOME"/.local/state/foo
test -d "$HOME"/.config/foo

test "$(readlink "$HOME"/.local/state/foo)" = ../../.config/foo

# Check that this will work safely a second time
systemd-run --user -p StateDirectory=foo -p ConfigurationDirectory=foo --wait true

( ! systemd-run --user -p StateDirectory=foo::ro --wait bash -c "echo foo >$HOME/.local/state/foo/baz")
( ! systemd-run --user -p StateDirectory=foo:bar:ro --wait bash -c "echo foo >$HOME/.local/state/foo/baz")
( ! test -f "$HOME"/.local/state/foo/baz)
test -L "$HOME"/.local/state/bar

rm "$HOME"/.local/state/foo
rmdir "$HOME"/.config/foo

# ConfigurationDirectory= accepts the flags field too, but no symlink destination
( ! systemd-run --user -p ConfigurationDirectory=quux::ro --wait bash -c "echo foo >$HOME/.config/quux/baz")
test -d "$HOME"/.config/quux
( ! test -f "$HOME"/.config/quux/baz)
( ! systemd-run --user -p ConfigurationDirectory=quux:link --wait true)

# A 'private' source is refused by the manager
( ! systemd-run --user -p StateDirectory=private/waldo::ro --wait true)
( ! test -e "$HOME"/.local/state/private)

# An empty assignment resets the list, so nothing is created below
systemd-run --user -p ConfigurationDirectory=corge -p ConfigurationDirectory= --wait true
( ! test -e "$HOME"/.config/corge)

# A flags field without a symlink destination must round-trip through the transient
# unit, i.e. it must not end up serialized with a literal "(null)" destination
systemd-run --user --unit=test-execdir-flags -p StateDirectory=waldo::ro -p ConfigurationDirectory=quux::ro sleep infinity
systemctl --user cat test-execdir-flags.service | grep "^StateDirectory=waldo::ro$" >/dev/null
systemctl --user cat test-execdir-flags.service | grep "^ConfigurationDirectory=quux::ro$" >/dev/null
systemctl --user daemon-reload
assert_eq "$(systemctl --user show -P StateDirectorySymlink test-execdir-flags.service)" "waldo::ro"
assert_eq "$(systemctl --user show -P ConfigurationDirectorySymlink test-execdir-flags.service)" "quux::ro"

# A literal colon in a directory name must survive the transient drop-in round-trip
systemd-run --user --unit=test-execdir-colon -p 'StateDirectory=grault\\:garply' sleep infinity
assert_eq "$(systemctl --user show -P StateDirectory test-execdir-colon.service)" "grault:garply"
systemctl --user daemon-reload
assert_eq "$(systemctl --user show -P StateDirectory test-execdir-colon.service)" "grault:garply"
