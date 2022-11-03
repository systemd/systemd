#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

if ! command -v systemd-firstboot >/dev/null; then
    echo "systemd-firstboot not found, skipping the test"
    exit 0
fi

at_exit() {
    if [[ -v ROOT && -n "$ROOT" ]]; then
        ls -lR "$ROOT"
        rm -fr "$ROOT"
    fi
}

trap at_exit EXIT

# Generated via `mkpasswd -m sha-512 -S foobarsalt password1`
# shellcheck disable=SC2016
ROOT_HASHED_PASSWORD1='$6$foobarsalt$YbwdaATX6IsFxvWbY3QcZj2gB31R/LFRFrjlFrJtTTqFtSfn4dfOAg/km2k4Sl.a2g7LOYDo31wMTaEsCo9j41'
# Generated via `mkpasswd -m sha-512 -S foobarsalt password2`
# shellcheck disable=SC2016
ROOT_HASHED_PASSWORD2='$6$foobarsalt$q.P2932zYMLbKnjFwIxPI8y3iuxeuJ2BgE372LcZMMnj3Gcg/9mJg2LPKUl.ha0TG/.fRNNnRQcLfzM0SNot3.'

# Create a minimal root so we don't modify the testbed
ROOT=test-root
mkdir -p "$ROOT/bin"
# Dummy shell for --root-shell=
touch "$ROOT/bin/fooshell" "$ROOT/bin/barshell"

systemd-firstboot --root="$ROOT" --locale=foo
grep -q "LANG=foo" "$ROOT/etc/locale.conf"
rm -fv "$ROOT/etc/locale.conf"
# FIXME: https://github.com/systemd/systemd/issues/25249
#systemd-firstboot --root="$ROOT" --locale-messages=foo
#grep -q "LC_MESSAGES=foo" "$ROOT/etc/locale.conf"
#rm -fv "$ROOT/etc/locale.conf"
systemd-firstboot --root="$ROOT" --locale=foo --locale-messages=bar
grep -q "LANG=foo" "$ROOT/etc/locale.conf"
grep -q "LC_MESSAGES=bar" "$ROOT/etc/locale.conf"

systemd-firstboot --root="$ROOT" --keymap=foo
grep -q "KEYMAP=foo" "$ROOT/etc/vconsole.conf"

systemd-firstboot --root="$ROOT" --timezone=Europe/Berlin
readlink "$ROOT/etc/localtime" | grep -q "Europe/Berlin"

systemd-firstboot --root="$ROOT" --hostname "foobar"
grep -q "foobar" "$ROOT/etc/hostname"

systemd-firstboot --root="$ROOT" --machine-id=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
grep -q "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" "$ROOT/etc/machine-id"

rm -fv "$ROOT/etc/passwd" "$ROOT/etc/shadow"
systemd-firstboot --root="$ROOT" --root-password=foo
grep -q "^root:x:0:0:" "$ROOT/etc/passwd"
grep -q "^root:" "$ROOT/etc/shadow"
rm -fv "$ROOT/etc/passwd" "$ROOT/etc/shadow"
echo "foo" >root.passwd
systemd-firstboot --root="$ROOT" --root-password-file=root.passwd
grep -q "^root:x:0:0:" "$ROOT/etc/passwd"
grep -q "^root:" "$ROOT/etc/shadow"
rm -fv "$ROOT/etc/passwd" "$ROOT/etc/shadow" root.passwd
# Set the shell together with the password, as firstboot won't touch
# /etc/passwd if it already exists
systemd-firstboot --root="$ROOT" --root-password-hashed="$ROOT_HASHED_PASSWORD1" --root-shell=/bin/fooshell
grep -q "^root:x:0:0:.*:/bin/fooshell$" "$ROOT/etc/passwd"
grep -q "^root:$ROOT_HASHED_PASSWORD1:" "$ROOT/etc/shadow"

systemd-firstboot --root="$ROOT" --kernel-command-line="foo.bar=42"
grep -q "foo.bar=42" "$ROOT/etc/kernel/cmdline"

# Configs should not get overwritten if they exist unless --force is used
systemd-firstboot --root="$ROOT" \
                  --locale=locale-overwrite \
                  --locale-messages=messages-overwrite \
                  --keymap=keymap-overwrite \
                  --timezone=CET \
                  --hostname=hostname-overwrite \
                  --machine-id=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
                  --root-password-hashed="$ROOT_HASHED_PASSWORD2" \
                  --root-shell=/bin/barshell \
                  --kernel-command-line="hello.world=0"
grep -q "LANG=foo" "$ROOT/etc/locale.conf"
grep -q "LC_MESSAGES=bar" "$ROOT/etc/locale.conf"
grep -q "KEYMAP=foo" "$ROOT/etc/vconsole.conf"
readlink "$ROOT/etc/localtime" | grep -q "Europe/Berlin$"
grep -q "foobar" "$ROOT/etc/hostname"
grep -q "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" "$ROOT/etc/machine-id"
grep -q "^root:x:0:0:.*:/bin/fooshell$" "$ROOT/etc/passwd"
grep -q "^root:$ROOT_HASHED_PASSWORD1:" "$ROOT/etc/shadow"
grep -q "foo.bar=42" "$ROOT/etc/kernel/cmdline"

# The same thing, but now with --force
systemd-firstboot --root="$ROOT" --force \
                  --locale=locale-overwrite \
                  --locale-messages=messages-overwrite \
                  --keymap=keymap-overwrite \
                  --timezone=CET \
                  --hostname=hostname-overwrite \
                  --machine-id=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
                  --root-password-hashed="$ROOT_HASHED_PASSWORD2" \
                  --root-shell=/bin/barshell \
                  --kernel-command-line="hello.world=0"
grep -q "LANG=locale-overwrite" "$ROOT/etc/locale.conf"
grep -q "LC_MESSAGES=messages-overwrite" "$ROOT/etc/locale.conf"
grep -q "KEYMAP=keymap-overwrite" "$ROOT/etc/vconsole.conf"
readlink "$ROOT/etc/localtime" | grep -q "/CET$"
grep -q "hostname-overwrite" "$ROOT/etc/hostname"
grep -q "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" "$ROOT/etc/machine-id"
grep -q "^root:x:0:0:.*:/bin/barshell$" "$ROOT/etc/passwd"
grep -q "^root:$ROOT_HASHED_PASSWORD2:" "$ROOT/etc/shadow"
grep -q "hello.world=0" "$ROOT/etc/kernel/cmdline"

# --copy-* options
rm -fr "$ROOT"
mkdir "$ROOT"
# Copy everything at once (--copy)
systemd-firstboot --root="$ROOT" --copy
diff /etc/locale.conf "$ROOT/etc/locale.conf"
diff <(awk -F: '/^root/ { print $7; }' /etc/passwd) <(awk -F: '/^root/ { print $7; }' "$ROOT/etc/passwd")
diff <(awk -F: '/^root/ { print $2; }' /etc/shadow) <(awk -F: '/^root/ { print $2; }' "$ROOT/etc/shadow")
[[ -e /etc/vconsole.conf ]] && diff /etc/vconsole.conf "$ROOT/etc/vconsole.conf"
[[ -e /etc/localtime ]] && diff <(readlink /etc/localtime) <(readlink "$ROOT/etc/localtime")
rm -fr "$ROOT"
mkdir "$ROOT"
# Copy everything at once, but now by using separate switches
systemd-firstboot --root="$ROOT" --copy-locale --copy-keymap --copy-timezone --copy-root-password --copy-root-shell
diff /etc/locale.conf "$ROOT/etc/locale.conf"
diff <(awk -F: '/^root/ { print $7; }' /etc/passwd) <(awk -F: '/^root/ { print $7; }' "$ROOT/etc/passwd")
diff <(awk -F: '/^root/ { print $2; }' /etc/shadow) <(awk -F: '/^root/ { print $2; }' "$ROOT/etc/shadow")
[[ -e /etc/vconsole.conf ]] && diff /etc/vconsole.conf "$ROOT/etc/vconsole.conf"
[[ -e /etc/localtime ]] && diff <(readlink /etc/localtime) <(readlink "$ROOT/etc/localtime")

# Assorted tests
rm -fr "$ROOT"
mkdir "$ROOT"

systemd-firstboot --root="$ROOT" --setup-machine-id
grep -E "[a-z0-9]{32}" "$ROOT/etc/machine-id"

systemd-firstboot --root="$ROOT" --delete-root-password
diff <(echo) <(awk -F: '/^root/ { print $2; }' "$ROOT/etc/shadow")
