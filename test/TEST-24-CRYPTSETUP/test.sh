#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="cryptsetup systemd setup"
IMAGE_NAME="cryptsetup"
IMAGE_ADDITIONAL_DATA_SIZE=100
TEST_NO_NSPAWN=1
TEST_FORCE_NEWIMAGE=1

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

PART_UUID="deadbeef-dead-dead-beef-000000000000"
DM_NAME="test24_varcrypt"
KERNEL_OPTIONS=(
    "rd.luks=1"
    "luks.name=$PART_UUID=$DM_NAME"
    "luks.key=$PART_UUID=/keyfile:LABEL=varcrypt_keydev"
    "luks.options=$PART_UUID=x-initrd.attach"
)
KERNEL_APPEND+=" ${KERNEL_OPTIONS[*]}"
QEMU_OPTIONS+=" -drive format=raw,cache=unsafe,file=${STATEDIR:?}/keydev.img"

check_result_qemu() {
    local ret

    mount_initdir

    cryptsetup luksOpen "${LOOPDEV:?}p4" "${DM_NAME:?}" <"$TESTDIR/keyfile"
    mount "/dev/mapper/$DM_NAME" "$initdir/var"

    check_result_common "${initdir:?}" && ret=0 || ret=$?

    _umount_dir "$initdir/var"
    _umount_dir "$initdir"
    cryptsetup luksClose "/dev/mapper/$DM_NAME"

    return $ret
}

test_create_image() {
    create_empty_image_rootdir

    echo -n test >"${TESTDIR:?}/keyfile"
    cryptsetup -q luksFormat --uuid="$PART_UUID" --pbkdf pbkdf2 --pbkdf-force-iterations 1000 "${LOOPDEV:?}p4" "$TESTDIR/keyfile"
    cryptsetup luksOpen "${LOOPDEV}p4" "${DM_NAME:?}" <"$TESTDIR/keyfile"
    mkfs.ext4 -L var "/dev/mapper/$DM_NAME"
    mkdir -p "${initdir:?}/var"
    mount "/dev/mapper/$DM_NAME" "$initdir/var"

    LOG_LEVEL=5

    setup_basic_environment
    mask_supporting_services

    install_dmevent
    generate_module_dependencies

    # Create a keydev
    dd if=/dev/zero of="${STATEDIR:?}/keydev.img" bs=1M count=16
    mkfs.ext4 -L varcrypt_keydev "$STATEDIR/keydev.img"
    mkdir -p "$STATEDIR/keydev"
    mount "$STATEDIR/keydev.img" "$STATEDIR/keydev"
    echo -n test >"$STATEDIR/keydev/keyfile"
    sync "$STATEDIR/keydev"
    umount "$STATEDIR/keydev"

    cat >>"$initdir/etc/fstab" <<EOF
/dev/mapper/$DM_NAME    /var    ext4    defaults 0 1
EOF

    # Forward journal messages to the console, so we have something
    # to investigate even if we fail to mount the encrypted /var
    echo ForwardToConsole=yes >>"$initdir/etc/systemd/journald.conf"

    # If $INITRD wasn't provided explicitly, generate a custom one with dm-crypt
    # support
    if [[ -z "$INITRD" ]]; then
        INITRD="${TESTDIR:?}/initrd.img"
        dinfo "Generating a custom initrd with dm-crypt support in '${INITRD:?}'"

        if command -v dracut >/dev/null; then
            dracut --force --verbose --add crypt "$INITRD"
        elif command -v mkinitcpio >/dev/null; then
            mkinitcpio --addhooks sd-encrypt --generate "$INITRD"
        elif command -v mkinitramfs >/dev/null; then
            # The cryptroot hook is provided by the cryptsetup-initramfs package
            if ! dpkg-query -s cryptsetup-initramfs; then
                derror "Missing 'cryptsetup-initramfs' package for dm-crypt support in initrd"
                return 1
            fi

            mkinitramfs -o "$INITRD"
        else
            dfatal "Unrecognized initrd generator, can't continue"
            return 1
        fi
    fi
}

cleanup_root_var() {
    mountpoint -q "$initdir/var" && umount "$initdir/var"
    [[ -b "/dev/mapper/${DM_NAME:?}" ]] && cryptsetup luksClose "/dev/mapper/$DM_NAME"
    mountpoint -q "${STATEDIR:?}/keydev" && umount "$STATEDIR/keydev"
}

test_cleanup() {
    # ignore errors, so cleanup can continue
    cleanup_root_var || :
    _test_cleanup
}

test_setup_cleanup() {
    cleanup_root_var || :
    cleanup_initdir
}

do_test "$@"
