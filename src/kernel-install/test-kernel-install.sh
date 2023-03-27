#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2235
set -eux
set -o pipefail

export SYSTEMD_LOG_LEVEL=debug

kernel_install="${1:?}"
plugin="${2:?}"
if [[ -d "${PROJECT_BUILD_ROOT:-}" ]]; then
    bootctl="${PROJECT_BUILD_ROOT}/bootctl"
else
    bootctl=
fi

D="$(mktemp --tmpdir --directory "test-kernel-install.XXXXXXXXXX")"

# shellcheck disable=SC2064
trap "rm -rf '$D'" EXIT INT QUIT PIPE
mkdir -p "$D/boot"
mkdir -p "$D/efi"
mkdir -p "$D/sources"

echo 'buzy image' >"$D/sources/linux"
echo 'the initrd' >"$D/sources/initrd"
echo 'the-token' >"$D/sources/entry-token"
echo 'opt1 opt2' >"$D/sources/cmdline"

cat >"$D/sources/install.conf" <<EOF
layout=bls
initrd_generator=none
# those are overridden by envvars
BOOT_ROOT="$D/badboot"
MACHINE_ID=badbadbadbadbadbad6abadbadbadbad
EOF

export KERNEL_INSTALL_CONF_ROOT="$D/sources"
export KERNEL_INSTALL_PLUGINS="$plugin"
export BOOT_ROOT="$D/boot"
export BOOT_MNT="$D/boot"
export MACHINE_ID='3e0484f3634a418b8e6a39e8828b03e3'

"$kernel_install" -v add 1.1.1 "$D/sources/linux" "$D/sources/initrd"

entry="$BOOT_ROOT/loader/entries/the-token-1.1.1.conf"
test -f "$entry"
grep -qE '^title ' "$entry"
grep -qE '^version +1.1.1' "$entry"
grep -qE '^options +opt1 opt2' "$entry"
grep -qE '^linux .*/the-token/1.1.1/linux' "$entry"
grep -qE '^initrd .*/the-token/1.1.1/initrd' "$entry"

grep -qE 'image' "$BOOT_ROOT/the-token/1.1.1/linux"
grep -qE 'initrd' "$BOOT_ROOT/the-token/1.1.1/initrd"

"$kernel_install" inspect
"$kernel_install" inspect "$D/sources/linux"

"$kernel_install" -v remove 1.1.1
test ! -e "$entry"
test ! -e "$BOOT_ROOT/the-token/1.1.1/linux"
test ! -e "$BOOT_ROOT/the-token/1.1.1/initrd"

# Invoke kernel-install as installkernel
ln -s --relative -v "$kernel_install" "$D/sources/installkernel"
"$D/sources/installkernel" -v 1.1.2 "$D/sources/linux" System.map /somedirignored

entry="$BOOT_ROOT/loader/entries/the-token-1.1.2.conf"
test -f "$entry"
grep -qE '^title ' "$entry"
grep -qE '^version +1.1.2' "$entry"
grep -qE '^options +opt1 opt2' "$entry"
grep -qE '^linux .*/the-token/1.1.2/linux' "$entry"
( ! grep -qE '^initrd' "$entry" )

grep -qE 'image' "$BOOT_ROOT/the-token/1.1.2/linux"
test ! -e "$BOOT_ROOT/the-token/1.1.2/initrd"

# Check installation with boot counting
echo '56' >"$D/sources/tries"

"$kernel_install" -v add 1.1.1 "$D/sources/linux" "$D/sources/initrd"
entry="$BOOT_ROOT/loader/entries/the-token-1.1.1+56.conf"
test -f "$entry"
grep -qE '^title ' "$entry"
grep -qE '^version +1.1.1' "$entry"
grep -qE '^options +opt1 opt2' "$entry"
grep -qE '^linux .*/the-token/1.1.1/linux' "$entry"
grep -qE '^initrd .*/the-token/1.1.1/initrd' "$entry"

grep -qE 'image' "$BOOT_ROOT/the-token/1.1.1/linux"
grep -qE 'initrd' "$BOOT_ROOT/the-token/1.1.1/initrd"

if test -x "$bootctl"; then
    echo "Testing bootctl"
    e2="${entry%+*}_2.conf"
    cp "$entry" "$e2"
    export SYSTEMD_ESP_PATH=/boot
    # We use --root so strip the root prefix from KERNEL_INSTALL_CONF_ROOT
    export KERNEL_INSTALL_CONF_ROOT="sources"

    # create file that is not referenced. Check if cleanup removes
    # it but leaves the rest alone
    :> "$BOOT_ROOT/the-token/1.1.2/initrd"
    "$bootctl" --root="$D" cleanup
    test ! -e "$BOOT_ROOT/the-token/1.1.2/initrd"
    test -e "$BOOT_ROOT/the-token/1.1.2/linux"
    test -e "$BOOT_ROOT/the-token/1.1.1/linux"
    test -e "$BOOT_ROOT/the-token/1.1.1/initrd"

    # now remove duplicated entry and make sure files are left over
    "$bootctl" --root="$D" unlink "${e2##*/}"
    test -e "$BOOT_ROOT/the-token/1.1.1/linux"
    test -e "$BOOT_ROOT/the-token/1.1.1/initrd"
    test -e "$entry"
    test ! -e "$e2"
    # remove last entry referencing those files
    entry_id="${entry##*/}"
    entry_id="${entry_id%+*}.conf"
    "$bootctl" --root="$D" unlink "$entry_id"
    test ! -e "$entry"
    test ! -e "$BOOT_ROOT/the-token/1.1.1/linux"
    test ! -e "$BOOT_ROOT/the-token/1.1.1/initrd"
fi

###########################################
# tests for --make-entry-directory=
###########################################

# disable all dropins
cat >"$D/00-skip.install" <<EOF
#!/bin/bash
exit 77
EOF
chmod +x "$D/00-skip.install"
export KERNEL_INSTALL_PLUGINS="$D/00-skip.install"

# drop layout= from install.conf
cat >"$D/sources/install.conf" <<EOF
initrd_generator=none
# those are overridden by envvars
BOOT_ROOT="$D/badboot"
MACHINE_ID=badbadbadbadbadbad6abadbadbadbad
EOF
export KERNEL_INSTALL_CONF_ROOT="$D/sources"

rm -rf "$BOOT_ROOT"
mkdir -p "$BOOT_ROOT"

# 1. defaults to 'auto', and the entry directory is created only when the layout is BLS
# 1.1 token directory does not exist -> layout is other.
"$kernel_install" -v add 1.1.1 "$D/sources/linux" "$D/sources/initrd"
test -e "$BOOT_ROOT/the-token/1.1.1" && { echo 'unexpected success'; exit 1; }
"$kernel_install" -v remove 1.1.1
test -e "$BOOT_ROOT/the-token/1.1.1" && { echo 'unexpected success'; exit 1; }

# 1.2 token directory exists -> layout is BLS
mkdir -p "$BOOT_ROOT/the-token"
"$kernel_install" -v add 1.1.1 "$D/sources/linux" "$D/sources/initrd"
test -d "$BOOT_ROOT/the-token/1.1.1"
"$kernel_install" -v remove 1.1.1
test -e "$BOOT_ROOT/the-token/1.1.1" && { echo 'unexpected success'; exit 1; }
rmdir "$BOOT_ROOT/the-token"

# 2. --make-entry-directory=yes
# 2.1 token directory does not exist -> layout is other.
"$kernel_install" -v --make-entry-directory=yes add 1.1.1 "$D/sources/linux" "$D/sources/initrd"
test -d "$BOOT_ROOT/the-token/1.1.1"
"$kernel_install" -v --make-entry-directory=yes remove 1.1.1
test -e "$BOOT_ROOT/the-token/1.1.1" && { echo 'unexpected success'; exit 1; }
test -d "$BOOT_ROOT/the-token"

# 2.2 token directory exists -> layout is BLS
mkdir -p "$BOOT_ROOT/the-token"
"$kernel_install" -v --make-entry-directory=yes add 1.1.1 "$D/sources/linux" "$D/sources/initrd"
test -d "$BOOT_ROOT/the-token/1.1.1"
"$kernel_install" -v --make-entry-directory=yes remove 1.1.1
test -e "$BOOT_ROOT/the-token/1.1.1" && { echo 'unexpected success'; exit 1; }
test -d "$BOOT_ROOT/the-token"
rmdir "$BOOT_ROOT/the-token"

# 3. --make-entry-directory=no
# 3.1 token directory does not exist -> layout is other.
"$kernel_install" -v --make-entry-directory=no add 1.1.1 "$D/sources/linux" "$D/sources/initrd"
test -e "$BOOT_ROOT/the-token/1.1.1" && { echo 'unexpected success'; exit 1; }
"$kernel_install" -v --make-entry-directory=no remove 1.1.1
test -e "$BOOT_ROOT/the-token/1.1.1" && { echo 'unexpected success'; exit 1; }

# 3.2 token directory exists -> layout is BLS
mkdir -p "$BOOT_ROOT/the-token"
"$kernel_install" -v --make-entry-directory=no add 1.1.1 "$D/sources/linux" "$D/sources/initrd"
test -e "$BOOT_ROOT/the-token/1.1.1" && { echo 'unexpected success'; exit 1; }
"$kernel_install" -v --make-entry-directory=no remove 1.1.1
test -e "$BOOT_ROOT/the-token/1.1.1" && { echo 'unexpected success'; exit 1; }
test -d "$BOOT_ROOT/the-token"
rmdir "$BOOT_ROOT/the-token"
