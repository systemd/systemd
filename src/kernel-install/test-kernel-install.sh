#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2235
set -eu
set -o pipefail

kernel_install="${1:?}"
plugin="${2:?}"

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

"$kernel_install" -v remove 1.1.1
test ! -f "$entry"
test ! -f "$BOOT_ROOT/the-token/1.1.1/linux"
test ! -f "$BOOT_ROOT/the-token/1.1.1/initrd"

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
