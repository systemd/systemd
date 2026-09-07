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

    systemctl --user stop test-execdir-flags.service test-execdir-colon.service test-execdir-raw.service
    rm -fr "$HOME"/.config/corge "$HOME"/.config/foo "$HOME"/.config/quux* "$HOME"/.local/state/bar "$HOME"/.local/state/foo \
           "$HOME"/.local/state/grault* "$HOME"/.local/state/private \
           "$HOME"/.local/state/waldo "$HOME"/.config/grault* \
           "$HOME"/.local/state/execdir-test "$HOME"/.config/execdir-test \
           "$HOME"/.cache/execdir-test "$HOME"/.local/state/log/execdir-test "$XDG_RUNTIME_DIR"/execdir-test
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

# Bypass the client parser to exercise the manager-side validation. Include a valid
# ExecStart= so an unrelated missing-command error cannot make the test pass.
if output=$(busctl --user call \
    org.freedesktop.systemd1 /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager StartTransientUnit \
    'ssa(sv)a(sa(sv))' test-execdir-raw.service fail 2 \
    ExecStart 'a(sasb)' 1 /usr/bin/true 1 /usr/bin/true false \
    ConfigurationDirectorySymlink 'a(sst)' 1 execdir-test/source execdir-test/link 0 \
    0 2>&1); then
    echo 'Manager accepted a ConfigurationDirectorySymlink destination' >&2
    exit 1
fi
[[ "$output" == *'Symlink destination is not supported for ConfigurationDirectory='* ]]

# A 'private' source is refused by the manager
( ! systemd-run --user -p StateDirectory=private/waldo::ro --wait true)
( ! test -e "$HOME"/.local/state/private)

# The reserved directory must not be created through a symlink destination either.
for type in Runtime State Cache Logs; do
    for destination in private private/execdir-test; do
        assert_fail systemd-run --user -p "${type}Directory=execdir-test/source:$destination" --wait true
    done
done

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
systemd-run --user --unit=test-execdir-colon \
    -p 'StateDirectory=grault\\:garply' -p 'ConfigurationDirectory=grault\\:garply' sleep infinity
assert_eq "$(systemctl --user show -P StateDirectory test-execdir-colon.service)" "grault:garply"
assert_eq "$(systemctl --user show -P ConfigurationDirectory test-execdir-colon.service)" "grault:garply"
systemctl --user daemon-reload
assert_eq "$(systemctl --user show -P StateDirectory test-execdir-colon.service)" "grault:garply"
assert_eq "$(systemctl --user show -P ConfigurationDirectory test-execdir-colon.service)" "grault:garply"

# Exercise both D-Bus signatures with names that need escaping at both the transient
# unit file and executor serialization layers. Read the typed property to avoid
# confusing systemctl's display escaping with the actual stored path.
for property in StateDirectory ConfigurationDirectory StateDirectorySymlink ConfigurationDirectorySymlink; do
    for name in 'with space' 'with"quote' 'with:colon'; do
        source="execdir-test/$name"
        destination=''
        if [[ "$property" == *Symlink ]]; then
            if [[ "$property" == StateDirectorySymlink ]]; then
                destination="execdir-test/link-$name"
            fi
            value=('a(sst)' 1 "$source" "$destination" 1)
        else
            value=(as 1 "$source")
        fi

        busctl --user call \
            org.freedesktop.systemd1 /org/freedesktop/systemd1 \
            org.freedesktop.systemd1.Manager StartTransientUnit \
            'ssa(sv)a(sa(sv))' test-execdir-raw.service fail 4 \
            Type s oneshot RemainAfterExit b true \
            ExecStart 'a(sasb)' 1 /usr/bin/true 1 /usr/bin/true false \
            "$property" "${value[@]}" 0
        systemctl --user start test-execdir-raw.service
        for phase in before after; do
            if [[ "$phase" == after ]]; then
                systemctl --user daemon-reload
                systemctl --user restart test-execdir-raw.service
            fi
            assert_eq "$(busctl --user --json=short get-property \
                org.freedesktop.systemd1 /org/freedesktop/systemd1/unit/test_2dexecdir_2draw_2eservice \
                org.freedesktop.systemd1.Service "$property" | jq -r \
                    'if .type == "as" then .data[0] else .data[0][0] end')" "$source"
            if [[ "$property" == *Symlink ]]; then
                assert_eq "$(systemctl --user show -P "$property" test-execdir-raw.service)" "$source:$destination:ro"
            fi
        done
        systemctl --user stop test-execdir-raw.service
    done
done
