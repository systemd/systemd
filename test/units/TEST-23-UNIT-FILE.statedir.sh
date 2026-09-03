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

    systemctl --user stop test-execdir-flags.service
    rm -fr "$HOME"/.local/state/waldo
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

# A flags field without a symlink destination must round-trip through the transient
# unit, i.e. it must not end up serialized with a literal "(null)" destination
systemd-run --user --unit=test-execdir-flags -p StateDirectory=waldo::ro sleep infinity
systemctl --user cat test-execdir-flags.service | grep "^StateDirectory=waldo::ro$" >/dev/null
systemctl --user daemon-reload
assert_eq "$(systemctl --user show -P StateDirectorySymlink test-execdir-flags.service)" "waldo::ro"
