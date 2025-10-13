#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2235
set -eux
set -o pipefail

export SYSTEMD_LOG_LEVEL=debug

kernel_install="${1:?}"
loaderentry_install="${2:?}"
uki_copy_install="${3:?}"
ukify="${4:-}"
ukify_install="${5:-}"
boot_stub="${6:-}"
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

# Create a 'devicetree' config file that points to a fake dtb file
echo 'subdir/whatever.dtb' >"$D/sources/devicetree"
mkdir "$D/sources/subdir"
echo 'DTBDTBDTBDTB' >"$D/sources/subdir/whatever.dtb"

export KERNEL_INSTALL_CONF_ROOT="$D/sources"
# We "install" multiple plugins, but control which ones will be active via install.conf.
KERNEL_INSTALL_PLUGINS="'${loaderentry_install}' '${uki_copy_install}'"
if [[ -n "$ukify_install" ]]; then
    # shellcheck disable=SC2089
    KERNEL_INSTALL_PLUGINS="'${ukify_install}' $KERNEL_INSTALL_PLUGINS"
fi
# shellcheck disable=SC2090
export KERNEL_INSTALL_PLUGINS
export BOOT_ROOT="$D/boot"
export BOOT_MNT="$D/boot"
export MACHINE_ID='3e0484f3634a418b8e6a39e8828b03e3'
export KERNEL_INSTALL_UKIFY="$ukify"
export KERNEL_INSTALL_BOOT_STUB="$boot_stub"
export KERNEL_INSTALL_READ_MACHINE_INFO="no"
export KERNEL_INSTALL_BYPASS="no"

# Test type#1 installation
"$kernel_install" -v add 1.1.1 "$D/sources/linux" "$D/sources/initrd"

entry="$BOOT_ROOT/loader/entries/the-token-1.1.1.conf"
test -f "$entry"
grep -qE '^title ' "$entry"
grep -qE '^version +1.1.1' "$entry"
grep -qE '^options +opt1 opt2' "$entry"
grep -qE '^linux .*/the-token/1.1.1/linux' "$entry"
grep -qE '^initrd .*/the-token/1.1.1/initrd' "$entry"
grep -qE '^devicetree .*/the-token/1.1.1/whatever.dtb' "$entry"

grep -qE 'image' "$BOOT_ROOT/the-token/1.1.1/linux"
grep -qE 'initrd' "$BOOT_ROOT/the-token/1.1.1/initrd"
grep -qE 'DTBDTB' "$BOOT_ROOT/the-token/1.1.1/whatever.dtb"

test -f /usr/lib/modules/"$(uname -r)"/vmlinuz && "$kernel_install" inspect
"$kernel_install" inspect "$D/sources/linux"

"$kernel_install" -v remove 1.1.1
test ! -e "$entry"
test ! -e "$BOOT_ROOT/the-token/1.1.1/linux"
test ! -e "$BOOT_ROOT/the-token/1.1.1/initrd"

# Test again with too many arguments for 'remove' command. See #28448.
"$kernel_install" -v add 1.1.1 "$D/sources/linux" "$D/sources/initrd"

test -f "$entry"
test -f "$BOOT_ROOT/the-token/1.1.1/linux"
test -f "$BOOT_ROOT/the-token/1.1.1/initrd"

"$kernel_install" -v remove 1.1.1 hoge foo bar
test ! -e "$entry"
test ! -e "$BOOT_ROOT/the-token/1.1.1/linux"
test ! -e "$BOOT_ROOT/the-token/1.1.1/initrd"

# Test --entry-type options
"$kernel_install" -v add 1.1.1 "$D/sources/linux" "$D/sources/initrd"
"$kernel_install" -v remove 1.1.1 --entry-type=type1
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
grep -qE '^devicetree .*/the-token/1.1.2/whatever.dtb' "$entry"

grep -qE 'image' "$BOOT_ROOT/the-token/1.1.2/linux"
test ! -e "$BOOT_ROOT/the-token/1.1.2/initrd"
grep -qE 'DTBDTB' "$BOOT_ROOT/the-token/1.1.2/whatever.dtb"

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

# Install UKI
if [ -f "$ukify" ]; then
    mkdir "$D/sources/install.conf.d"
    cat >>"$D/sources/install.conf.d/override.conf" <<EOF
layout=uki
uki_generator=ukify
EOF

    "$kernel_install" -v add 1.1.3 "$D/sources/linux" "$D/sources/initrd"
    uki="${BOOT_ROOT}/EFI/Linux/the-token-1.1.3+56.efi"
    test -f "$uki"

    if [ -x "$bootctl" ]; then
        "$bootctl" kernel-inspect "$uki" | grep -qE 'Kernel Type: +uki$'
        "$bootctl" kernel-inspect "$uki" | grep -qE 'Version: +1\.1\.3$'
        "$bootctl" kernel-inspect "$uki" | grep -qE 'Cmdline: +opt1 opt2$'
    fi

    "$ukify" inspect "$uki" | grep -qE '^.sbat'
    "$ukify" inspect "$uki" | grep -qE '^.cmdline'
    "$ukify" inspect "$uki" | grep -qE '^.uname'
    "$ukify" inspect "$uki" | grep -qE '^.initrd'
    "$ukify" inspect "$uki" | grep -qE '^.linux'
    "$ukify" inspect "$uki" | grep -qE '^.dtb'

    rm "$D/sources/install.conf.d/override.conf"
fi

# Test bootctl
if [ -x "$bootctl" ]; then
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
test ! -e "$BOOT_ROOT/the-token/1.1.1"
"$kernel_install" -v remove 1.1.1
test ! -e "$BOOT_ROOT/the-token/1.1.1"

# 1.2 token directory exists -> layout is BLS
mkdir -p "$BOOT_ROOT/the-token"
"$kernel_install" -v add 1.1.1 "$D/sources/linux" "$D/sources/initrd"
test -d "$BOOT_ROOT/the-token/1.1.1"
"$kernel_install" -v remove 1.1.1
test ! -e "$BOOT_ROOT/the-token/1.1.1"
rmdir "$BOOT_ROOT/the-token"

# 2. --make-entry-directory=yes
# 2.1 token directory does not exist -> layout is other.
"$kernel_install" -v --make-entry-directory=yes add 1.1.1 "$D/sources/linux" "$D/sources/initrd"
test -d "$BOOT_ROOT/the-token/1.1.1"
"$kernel_install" -v --make-entry-directory=yes remove 1.1.1
test ! -e "$BOOT_ROOT/the-token/1.1.1"
test -d "$BOOT_ROOT/the-token"

# 2.2 token directory exists -> layout is BLS
mkdir -p "$BOOT_ROOT/the-token"
"$kernel_install" -v --make-entry-directory=yes add 1.1.1 "$D/sources/linux" "$D/sources/initrd"
test -d "$BOOT_ROOT/the-token/1.1.1"
"$kernel_install" -v --make-entry-directory=yes remove 1.1.1
test ! -e "$BOOT_ROOT/the-token/1.1.1"
test -d "$BOOT_ROOT/the-token"
rmdir "$BOOT_ROOT/the-token"

# 3. --make-entry-directory=no
# 3.1 token directory does not exist -> layout is other.
"$kernel_install" -v --make-entry-directory=no add 1.1.1 "$D/sources/linux" "$D/sources/initrd"
test ! -e "$BOOT_ROOT/the-token/1.1.1"
"$kernel_install" -v --make-entry-directory=no remove 1.1.1
test ! -e "$BOOT_ROOT/the-token/1.1.1"

# 3.2 token directory exists -> layout is BLS
mkdir -p "$BOOT_ROOT/the-token"
"$kernel_install" -v --make-entry-directory=no add 1.1.1 "$D/sources/linux" "$D/sources/initrd"
test ! -e "$BOOT_ROOT/the-token/1.1.1"
"$kernel_install" -v --make-entry-directory=no remove 1.1.1
test ! -e "$BOOT_ROOT/the-token/1.1.1"
test -d "$BOOT_ROOT/the-token"
rmdir "$BOOT_ROOT/the-token"

###########################################
# tests for --entry-token=
###########################################
"$kernel_install" -v --make-entry-directory=yes --entry-token=machine-id add 1.1.1 "$D/sources/linux" "$D/sources/initrd"
test -d "$BOOT_ROOT/$MACHINE_ID/1.1.1"
"$kernel_install" -v --make-entry-directory=yes --entry-token=machine-id remove 1.1.1
test ! -e "$BOOT_ROOT/$MACHINE_ID/1.1.1"
test -d "$BOOT_ROOT/$MACHINE_ID"
rmdir "$BOOT_ROOT/$MACHINE_ID"

"$kernel_install" -v --make-entry-directory=yes --entry-token=literal:hoge add 1.1.1 "$D/sources/linux" "$D/sources/initrd"
test -d "$BOOT_ROOT/hoge/1.1.1"
"$kernel_install" -v --make-entry-directory=yes --entry-token=literal:hoge remove 1.1.1
test ! -e "$BOOT_ROOT/hoge/1.1.1"
test -d "$BOOT_ROOT/hoge"
rmdir "$BOOT_ROOT/hoge"

###########################################
# tests for --json=
###########################################
output="$("$kernel_install" -v --json=pretty inspect 1.1.1 "$D/sources/linux")"

diff -u <(echo "$output") - >&2 <<EOF
{
	"MachineID" : "3e0484f3634a418b8e6a39e8828b03e3",
	"KernelImageType" : "unknown",
	"Layout" : "other",
	"BootRoot" : "$BOOT_ROOT",
	"EntryTokenType" : "literal",
	"EntryToken" : "the-token",
	"EntryDirectory" : "$BOOT_ROOT/the-token/1.1.1",
	"KernelVersion" : "1.1.1",
	"Kernel" : "$D/sources/linux",
	"Initrds" : null,
	"InitrdGenerator" : "none",
	"UKIGenerator" : null,
	"Plugins" : [
		"$D/00-skip.install"
	],
	"PluginEnvironment" : [
		"LC_COLLATE=$SYSTEMD_DEFAULT_LOCALE",
		"KERNEL_INSTALL_VERBOSE=1",
		"KERNEL_INSTALL_IMAGE_TYPE=unknown",
		"KERNEL_INSTALL_MACHINE_ID=3e0484f3634a418b8e6a39e8828b03e3",
		"KERNEL_INSTALL_ENTRY_TOKEN=the-token",
		"KERNEL_INSTALL_BOOT_ROOT=$BOOT_ROOT",
		"KERNEL_INSTALL_LAYOUT=other",
		"KERNEL_INSTALL_INITRD_GENERATOR=none",
		"KERNEL_INSTALL_UKI_GENERATOR=",
		"KERNEL_INSTALL_STAGING_AREA=/tmp/kernel-install.staging.XXXXXX"
	]
}
EOF

###########################################
# tests for propagation of plugin failure (issue #30087)
###########################################
cat >"$D/00-plugin-skip" <<EOF
#!/usr/bin/env bash
exit 77
EOF
chmod +x "$D/00-plugin-skip"

cat >"$D/10-plugin-fail" <<EOF
#!/usr/bin/env bash
exit 42
EOF
chmod +x "$D/10-plugin-fail"

# Exit code 77 means remaining plugins will be skipped.
KERNEL_INSTALL_PLUGINS="$D/00-plugin-skip $D/10-plugin-fail" "$kernel_install" -v add 1.1.1 "$D/sources/linux" "$D/sources/initrd"

# Other non-zero exit code will be propagated.
set +e
KERNEL_INSTALL_PLUGINS="$D/10-plugin-fail" "$kernel_install" -v add 1.1.1 "$D/sources/linux" "$D/sources/initrd"
ret=$?
set -e
test "$ret" -eq "42"
