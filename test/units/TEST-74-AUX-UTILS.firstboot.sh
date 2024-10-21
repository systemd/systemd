#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

if ! command -v systemd-firstboot >/dev/null; then
    echo "systemd-firstboot not found, skipping the test"
    exit 0
fi

at_exit() {
    if [[ -n "${ROOT:-}" ]]; then
        ls -lR "$ROOT"
        grep -r . "$ROOT/etc" || :
        rm -fr "$ROOT"
    fi

    restore_locale
}

trap at_exit EXIT

# Generated via `mkpasswd -m sha-512 -S foobarsalt password1`
# shellcheck disable=SC2016
ROOT_HASHED_PASSWORD1='$6$foobarsalt$YbwdaATX6IsFxvWbY3QcZj2gB31R/LFRFrjlFrJtTTqFtSfn4dfOAg/km2k4Sl.a2g7LOYDo31wMTaEsCo9j41'
# Generated via `mkpasswd -m sha-512 -S foobarsalt password2`
# shellcheck disable=SC2016
ROOT_HASHED_PASSWORD2='$6$foobarsalt$q.P2932zYMLbKnjFwIxPI8y3iuxeuJ2BgE372LcZMMnj3Gcg/9mJg2LPKUl.ha0TG/.fRNNnRQcLfzM0SNot3.'

if [[ -f /etc/locale.conf ]]; then
    cp /etc/locale.conf /tmp/locale.conf.bak
fi

# Debian/Ubuntu specific file
if [[ -f /etc/default/locale ]]; then
    cp /etc/default/locale /tmp/default-locale.bak
fi

if [[ -f /etc/locale.gen ]]; then
    cp /etc/locale.gen /tmp/locale.gen.bak
fi

# Make sure at least two locales exist (C.UTF-8 and en_US.UTF-8) as systemd-firstboot --prompt-locale will
# skip writing the locale if it detects only one is installed.
generate_locale en_US.UTF-8

# Debian and Ubuntu use /etc/default/locale instead of /etc/locale.conf. Make
# sure we use the appropriate path for locale configuration.
LOCALE_PATH="/etc/locale.conf"
[ -e "$LOCALE_PATH" ] || LOCALE_PATH="/etc/default/locale"
[ -e "$LOCALE_PATH" ] || systemd-firstboot --locale=C.UTF-8

# Create a minimal root so we don't modify the testbed
ROOT=test-root
mkdir -p "$ROOT/bin"
# Dummy shell for --root-shell=
touch "$ROOT/bin/fooshell" "$ROOT/bin/barshell"

systemd-firstboot --root="$ROOT" --locale=foo
grep -q "LANG=foo" "$ROOT$LOCALE_PATH"
rm -fv "$ROOT$LOCALE_PATH"
systemd-firstboot --root="$ROOT" --locale-messages=foo
grep -q "LC_MESSAGES=foo" "$ROOT$LOCALE_PATH"
rm -fv "$ROOT$LOCALE_PATH"
systemd-firstboot --root="$ROOT" --locale=foo --locale-messages=bar
grep -q "LANG=foo" "$ROOT$LOCALE_PATH"
grep -q "LC_MESSAGES=bar" "$ROOT$LOCALE_PATH"

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
grep -q "^root:[^!*]" "$ROOT/etc/shadow"
rm -fv "$ROOT/etc/passwd" "$ROOT/etc/shadow"
echo "foo" >root.passwd
systemd-firstboot --root="$ROOT" --root-password-file=root.passwd
grep -q "^root:x:0:0:" "$ROOT/etc/passwd"
grep -q "^root:[^!*]" "$ROOT/etc/shadow"
rm -fv "$ROOT/etc/passwd" "$ROOT/etc/shadow" root.passwd
# Make sure the root password is set if /etc/passwd and /etc/shadow exist but
# don't have a root entry.
touch "$ROOT/etc/passwd" "$ROOT/etc/shadow"
systemd-firstboot --root="$ROOT" --root-password=foo
grep -q "^root:x:0:0:" "$ROOT/etc/passwd"
grep -q "^root:[^!*]" "$ROOT/etc/shadow"
rm -fv "$ROOT/etc/passwd" "$ROOT/etc/shadow"
# If /etc/passwd and /etc/shadow exist, they will only be updated if the shadow
# password is !unprovisioned.
echo "root:x:0:0:root:/root:/bin/sh" >"$ROOT/etc/passwd"
echo "root:!test:::::::" >"$ROOT/etc/shadow"
systemd-firstboot --root="$ROOT" --root-password=foo
grep -q "^root:x:0:0:" "$ROOT/etc/passwd"
grep -q "^root:!test:" "$ROOT/etc/shadow"
rm -fv "$ROOT/etc/passwd" "$ROOT/etc/shadow"
echo "root:x:0:0:root:/root:/bin/sh" >"$ROOT/etc/passwd"
echo "root:!unprovisioned:::::::" >"$ROOT/etc/shadow"
systemd-firstboot --root="$ROOT" --root-password=foo
grep -q "^root:x:0:0:" "$ROOT/etc/passwd"
grep -q "^root:[^!*]" "$ROOT/etc/shadow"
rm -fv "$ROOT/etc/passwd" "$ROOT/etc/shadow"
systemd-firstboot --root="$ROOT" --root-password-hashed="$ROOT_HASHED_PASSWORD1"
grep -q "^root:x:0:0:" "$ROOT/etc/passwd"
grep -q "^root:$ROOT_HASHED_PASSWORD1:" "$ROOT/etc/shadow"
rm -fv "$ROOT/etc/passwd" "$ROOT/etc/shadow"
systemd-firstboot --root="$ROOT" --root-shell=/bin/fooshell
grep -q "^root:x:0:0:.*:/bin/fooshell$" "$ROOT/etc/passwd"
grep -q "^root:!\*:" "$ROOT/etc/shadow"
rm -fv "$ROOT/etc/passwd" "$ROOT/etc/shadow"
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
                  --timezone=Europe/Berlin \
                  --hostname=hostname-overwrite \
                  --machine-id=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
                  --root-password-hashed="$ROOT_HASHED_PASSWORD2" \
                  --root-shell=/bin/barshell \
                  --kernel-command-line="hello.world=0"
grep -q "LANG=foo" "$ROOT$LOCALE_PATH"
grep -q "LC_MESSAGES=bar" "$ROOT$LOCALE_PATH"
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
                  --timezone=Europe/Berlin \
                  --hostname=hostname-overwrite \
                  --machine-id=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
                  --root-password-hashed="$ROOT_HASHED_PASSWORD2" \
                  --root-shell=/bin/barshell \
                  --kernel-command-line="hello.world=0"
grep -q "LANG=locale-overwrite" "$ROOT$LOCALE_PATH"
grep -q "LC_MESSAGES=messages-overwrite" "$ROOT$LOCALE_PATH"
grep -q "KEYMAP=keymap-overwrite" "$ROOT/etc/vconsole.conf"
readlink "$ROOT/etc/localtime" | grep -q "/Europe/Berlin$"
grep -q "hostname-overwrite" "$ROOT/etc/hostname"
grep -q "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" "$ROOT/etc/machine-id"
grep -q "^root:x:0:0:.*:/bin/barshell$" "$ROOT/etc/passwd"
grep -q "^root:$ROOT_HASHED_PASSWORD2:" "$ROOT/etc/shadow"
grep -q "hello.world=0" "$ROOT/etc/kernel/cmdline"

# Test that --reset removes all files configured by firstboot.
systemd-firstboot --root="$ROOT" --reset
[[ ! -e "$ROOT/etc/locale.conf" ]]
[[ ! -e "$ROOT/etc/vconsole.conf" ]]
[[ ! -e "$ROOT/etc/localtime" ]]
[[ ! -e "$ROOT/etc/hostname" ]]
[[ ! -e "$ROOT/etc/machine-id" ]]
[[ ! -e "$ROOT/etc/kernel/cmdline" ]]

# --copy-* options
rm -fr "$ROOT"
mkdir "$ROOT"
# Copy everything at once (--copy)
systemd-firstboot --root="$ROOT" --copy
diff $LOCALE_PATH "$ROOT$LOCALE_PATH"
diff <(awk -F: '/^root/ { print $7; }' /etc/passwd) <(awk -F: '/^root/ { print $7; }' "$ROOT/etc/passwd")
diff <(awk -F: '/^root/ { print $2; }' /etc/shadow) <(awk -F: '/^root/ { print $2; }' "$ROOT/etc/shadow")
[[ -e /etc/vconsole.conf ]] && diff /etc/vconsole.conf "$ROOT/etc/vconsole.conf"
[[ -e /etc/localtime ]] && diff <(readlink /etc/localtime) <(readlink "$ROOT/etc/localtime")
rm -fr "$ROOT"
mkdir "$ROOT"
# Copy everything at once, but now by using separate switches
systemd-firstboot --root="$ROOT" --copy-locale --copy-keymap --copy-timezone --copy-root-password --copy-root-shell
diff $LOCALE_PATH "$ROOT$LOCALE_PATH"
diff <(awk -F: '/^root/ { print $7; }' /etc/passwd) <(awk -F: '/^root/ { print $7; }' "$ROOT/etc/passwd")
diff <(awk -F: '/^root/ { print $2; }' /etc/shadow) <(awk -F: '/^root/ { print $2; }' "$ROOT/etc/shadow")
[[ -e /etc/vconsole.conf ]] && diff /etc/vconsole.conf "$ROOT/etc/vconsole.conf"
[[ -e /etc/localtime ]] && diff <(readlink /etc/localtime) <(readlink "$ROOT/etc/localtime")

# --prompt-* options
rm -fr "$ROOT"
mkdir -p "$ROOT/bin"
touch "$ROOT/bin/fooshell" "$ROOT/bin/barshell"
# Temporarily disable pipefail to avoid `echo: write error: Broken pipe
set +o pipefail
# We can do only limited testing here, since it's all an interactive stuff, so
# --prompt is skipped on purpose and only limited --prompt-root-password
# testing can be done.
echo -ne "\nfoo\nbar\n" | systemd-firstboot --root="$ROOT" --prompt-locale
grep -q "LANG=foo" "$ROOT$LOCALE_PATH"
grep -q "LC_MESSAGES=bar" "$ROOT$LOCALE_PATH"
# systemd-firstboot in prompt-keymap mode requires keymaps to be installed so
# it can present them as a list to the user. As Debian does not ship/provide
# compatible keymaps (from the kbd package), skip this test if the keymaps are
# missing.
if [ -d "/usr/share/keymaps/" ] || [ -d "/usr/share/kbd/keymaps/" ] || [ -d "/usr/lib/kbd/keymaps/" ] ; then
   echo -ne "\nfoo\n" | systemd-firstboot --root="$ROOT" --prompt-keymap
   grep -q "KEYMAP=foo" "$ROOT/etc/vconsole.conf"
fi
echo -ne "\nEurope/Berlin\n" | systemd-firstboot --root="$ROOT" --prompt-timezone
readlink "$ROOT/etc/localtime" | grep -q "Europe/Berlin$"
echo -ne "\nfoobar\n" | systemd-firstboot --root="$ROOT" --prompt-hostname
grep -q "foobar" "$ROOT/etc/hostname"
# With no root password provided, a locked account should be created.
systemd-firstboot --root="$ROOT" --prompt-root-password </dev/null
grep -q "^root:x:0:0:" "$ROOT/etc/passwd"
grep -q "^root:!\*:" "$ROOT/etc/shadow"
rm -fv "$ROOT/etc/passwd" "$ROOT/etc/shadow"
echo -ne "\n/bin/fooshell\n" | systemd-firstboot --root="$ROOT" --prompt-root-shell
grep -q "^root:.*:0:0:.*:/bin/fooshell$" "$ROOT/etc/passwd"
# Existing files should not get overwritten
echo -ne "\n/bin/barshell\n" | systemd-firstboot --root="$ROOT" --prompt-root-shell
grep -q "^root:.*:0:0:.*:/bin/fooshell$" "$ROOT/etc/passwd"
# Now without the welcome screen but with force
echo -ne "/bin/barshell\n" | systemd-firstboot --root="$ROOT" --force --prompt-root-shell --welcome=no
grep -q "^root:.*:0:0:.*:/bin/barshell$" "$ROOT/etc/passwd"
# Re-enable pipefail
set -o pipefail

# --prompt-* options with credentials. Unfortunately, with --root the
# --systemd.firstboot kernel command line option is ignored, so that can't be
# --tested.
rm -fr "$ROOT"
mkdir -p "$ROOT/bin"
touch "$ROOT/bin/fooshell" "$ROOT/bin/barshell"
systemd-run --wait --pipe --service-type=exec \
    -p SetCredential=firstboot.locale:foo \
    -p SetCredential=firstboot.locale-messages:bar \
    -p SetCredential=firstboot.keymap:foo \
    -p SetCredential=firstboot.timezone:Europe/Berlin \
    -p SetCredential=passwd.hashed-password.root:"$ROOT_HASHED_PASSWORD1" \
    -p SetCredential=passwd.shell.root:/bin/fooshell \
    systemd-firstboot \
    --root="$ROOT" \
    --prompt-locale \
    --prompt-keymap \
    --prompt-timezone \
    --prompt-root-password \
    --prompt-root-shell \
    </dev/null
grep -q "LANG=foo" "$ROOT$LOCALE_PATH"
grep -q "LC_MESSAGES=bar" "$ROOT$LOCALE_PATH"
grep -q "KEYMAP=foo" "$ROOT/etc/vconsole.conf"
readlink "$ROOT/etc/localtime" | grep -q "Europe/Berlin$"
grep -q "^root:x:0:0:.*:/bin/fooshell$" "$ROOT/etc/passwd"
grep -q "^root:$ROOT_HASHED_PASSWORD1:" "$ROOT/etc/shadow"

# Assorted tests
rm -fr "$ROOT"
mkdir "$ROOT"

systemd-firstboot --root="$ROOT" --setup-machine-id
grep -E "[a-z0-9]{32}" "$ROOT/etc/machine-id"
rm -fv "$ROOT/etc/machine-id"

systemd-firstboot --root="$ROOT" --delete-root-password
grep -q "^root:x:0:0:" "$ROOT/etc/passwd"
grep -q "^root::" "$ROOT/etc/shadow"
rm -fv "$ROOT/etc/passwd" "$ROOT/etc/shadow"

(! systemd-firstboot --root="$ROOT" --root-shell=/bin/nonexistentshell)
(! systemd-firstboot --root="$ROOT" --machine-id=invalidmachineid)
(! systemd-firstboot --root="$ROOT" --timezone=Foo/Bar)
