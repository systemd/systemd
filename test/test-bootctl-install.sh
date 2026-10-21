#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Offline tests for "bootctl install" and "bootctl update" on a temporary root directory, whose /boot/ is a
# plain directory used as ESP. EFI variables are never touched.
#
# The boot loader "binaries" used here are plain text files, not PE images. "install" copies them as they
# are, which suffices to check what gets installed. As they carry no version information, "update" refuses
# to put them in place of an installed boot loader (get_file_version() fails with -ESRCH), hence version
# comparisons are not covered here.
#
# Arguments: the bootctl binary, and the directory it installs boot loaders from (BOOTLIBDIR).
set -eux
set -o pipefail

bootctl="${1:?}"
BOOTLIBDIR="${2:?}"

ARCH="$("$bootctl" --print-efi-architecture)"
if [[ -z "$ARCH" ]]; then
    echo "No EFI architecture known for this system, skipping tests" >&2
    exit 77
fi
if [[ "$ARCH" == aa64 ]]; then
    OTHER_ARCH=x64
else
    OTHER_ARCH=aa64
fi

WORKDIR="$(mktemp -d -t test-bootctl-install.XXXXXX)"
trap 'rm -rf "$WORKDIR"' EXIT
LOG="$WORKDIR/bootctl.log"
ROOT_COUNT=0

new_root() {
    # A fresh root with an empty boot loader source directory, an empty ESP, and a machine ID to derive
    # the boot entry token from
    ROOT_COUNT=$((ROOT_COUNT + 1))
    ROOT="$WORKDIR/root$ROOT_COUNT"
    SRC="$ROOT$BOOTLIBDIR"
    ESP="$ROOT/boot"
    mkdir -p "$SRC" "$ESP" "$ROOT/etc"
    echo 0123456789abcdef0123456789abcdef >"$ROOT/etc/machine-id"
}

make_loader() {
    # Plain text instead of a PE binary, hence without version information. The tag tells files apart.
    printf 'Not really systemd-boot (%s)\n' "${2:?}" >"${1:?}"
}

run_bootctl() {
    local rc=0

    # Use the ESP as $BOOT too, never touch EFI variables, and make sure --graceful is not implied by
    # chroot detection
    env -u KERNEL_INSTALL_CONF_ROOT \
        SYSTEMD_ESP_PATH=/boot \
        SYSTEMD_XBOOTLDR_PATH=/boot \
        SYSTEMD_IN_CHROOT=0 \
        SYSTEMD_LOG_TARGET=console \
        "$bootctl" --root="$ROOT" --install-source=image --no-variables "$@" 2>"$LOG" || rc=$?
    cat "$LOG" >&2
    return "$rc"
}

check_no_loader() {
    # "install" must fail because there is no boot loader to install, without installing one
    (! run_bootctl "$@" install)
    grep -F "No 'systemd-boot" "$LOG" >/dev/null
    test ! -e "$ESP/EFI/systemd/systemd-boot$ARCH.efi"
    test ! -e "$ESP/EFI/BOOT/BOOT${ARCH^^}.EFI"
}

check_installed() {
    # $1 is installed as systemd-boot and as the default boot loader for architecture $2
    cmp "${1:?}" "$ESP/EFI/systemd/systemd-boot${2:?}.efi"
    cmp "$1" "$ESP/EFI/BOOT/BOOT${2^^}.EFI"
}

# A missing source directory has always been refused. Also check that this is where bootctl looks for boot
# loaders, i.e. that the directory we were passed is right, as the tests below are meaningless otherwise.
new_root
rmdir "$SRC"
(! run_bootctl install)
grep -F "'$BOOTLIBDIR'" "$LOG" >/dev/null

# https://github.com/systemd/systemd/issues/41312: the source directory exists, but has no boot loader
# for the local architecture
new_root
check_no_loader

new_root
echo "Nothing to see here." >"$SRC/README"
check_no_loader

new_root
echo "Not a boot loader." >"$SRC/other$ARCH.efi"
check_no_loader

new_root
echo stub >"$SRC/linux$ARCH.efi.stub"
echo addon >"$SRC/addon$ARCH.efi.stub"
check_no_loader
check_no_loader --all-architectures

# Neither is a binary whose name merely starts with "systemd-boot" (it is not what becomes BOOT<ARCH>.EFI)
new_root
make_loader "$SRC/systemd-boot-extra$ARCH.efi" lookalike
check_no_loader

new_root
make_loader "$SRC/systemd-boot$OTHER_ARCH.efi" other-arch
check_no_loader
# ... which is fine when installing for all architectures
run_bootctl --all-architectures install
check_installed "$SRC/systemd-boot$OTHER_ARCH.efi" "$OTHER_ARCH"

# --graceful does not apply to "install" (unless running in a chroot)
new_root
check_no_loader --graceful

# Other errors take precedence over a missing boot loader
new_root
mkdir "$SRC/other$ARCH.efi"
(! run_bootctl install)
grep -F "other$ARCH.efi" "$LOG" >/dev/null
(! grep -F "No 'systemd-boot" "$LOG" >/dev/null)

# Unsigned boot loader, UKI stubs are not installed
new_root
make_loader "$SRC/systemd-boot$ARCH.efi" unsigned
echo stub >"$SRC/linux$ARCH.efi.stub"
run_bootctl install
check_installed "$SRC/systemd-boot$ARCH.efi" "$ARCH"
test ! -e "$ESP/EFI/systemd/linux$ARCH.efi.stub"

# Signed boot loader, installed without the .signed suffix
new_root
make_loader "$SRC/systemd-boot$ARCH.efi.signed" signed
run_bootctl install
check_installed "$SRC/systemd-boot$ARCH.efi.signed" "$ARCH"
test ! -e "$ESP/EFI/systemd/systemd-boot$ARCH.efi.signed"

# The signed boot loader is preferred over the unsigned one
new_root
make_loader "$SRC/systemd-boot$ARCH.efi" unsigned
make_loader "$SRC/systemd-boot$ARCH.efi.signed" signed
run_bootctl install
check_installed "$SRC/systemd-boot$ARCH.efi.signed" "$ARCH"

# "update" does nothing if systemd-boot is not installed, and in particular does not complain about the
# empty source directory
new_root
run_bootctl update
test ! -e "$ESP/EFI"

new_root
make_loader "$SRC/systemd-boot$ARCH.efi" installed
run_bootctl install
cp "$SRC/systemd-boot$ARCH.efi" "$WORKDIR/installed.efi"

# "update" without a boot loader to update to fails, except with --graceful
rm "$SRC/systemd-boot$ARCH.efi"
(! run_bootctl update)
grep -F "No 'systemd-boot$ARCH.efi'" "$LOG" >/dev/null
run_bootctl --graceful update
check_installed "$WORKDIR/installed.efi" "$ARCH"

# "update" does not put a boot loader without version information (like all of them here) in place of an
# installed one, as there is no version to compare (-ESRCH). That is an error, except with --graceful,
# but in neither case one about a missing boot loader: it was found after all.
make_loader "$SRC/systemd-boot$ARCH.efi" unversioned
(! run_bootctl update)
grep -F "does not carry version information" "$LOG" >/dev/null
(! grep -F "No 'systemd-boot" "$LOG" >/dev/null)
run_bootctl --graceful update
(! grep -F "No 'systemd-boot" "$LOG" >/dev/null)
check_installed "$WORKDIR/installed.efi" "$ARCH"
