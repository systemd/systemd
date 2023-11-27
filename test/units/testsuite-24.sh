#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# TODO:
#   - /proc/cmdline parsing
#   - expect + interactive auth?

# We set up an encrypted /var partition which should get mounted automatically
# on boot
mountpoint /var

systemctl --state=failed --no-legend --no-pager | tee /failed
if [[ -s /failed ]]; then
    echo >&2 "Found units in failed state"
    exit 1
fi

at_exit() {
    set +e

    mountpoint -q /proc/cmdline && umount /proc/cmdline
    rm -f /etc/crypttab
    [[ -e /tmp/crypttab.bak ]] && cp -fv /tmp/crypttab.bak /etc/crypttab
    [[ -n "${STORE_LOOP:-}" ]] && losetup -d "$STORE_LOOP"
    [[ -n "${WORKDIR:-}" ]] && rm -rf "$WORKDIR"

    systemctl daemon-reload
}

trap at_exit EXIT

cryptsetup_start_and_check() {
    local expect_fail=0
    local ec volume unit

    if [[ "${1:?}" == "-f" ]]; then
        expect_fail=1
        shift
    fi

    for volume in "$@"; do
        unit="systemd-cryptsetup@$volume.service"

        # The unit existence check should always pass
        [[ "$(systemctl show -P LoadState "$unit")" == loaded ]]
        systemctl list-unit-files "$unit"

        systemctl start "$unit" && ec=0 || ec=$?
        if [[ "$expect_fail" -ne 0 ]]; then
            if [[ "$ec" -eq 0 ]]; then
                echo >&2 "Unexpected pass when starting $unit"
                return 1
            fi

            return 0
        fi

        if [[ "$ec" -ne 0 ]]; then
            echo >&2 "Unexpected fail when starting $unit"
            return 1
        fi

        systemctl status "$unit"
        test -e "/dev/mapper/$volume"
        systemctl stop "$unit"
        test ! -e "/dev/mapper/$volume"
    done

    return 0
}

# Note: some stuff (especially TPM-related) is already tested by TEST-70-TPM2,
#       so focus more on other areas instead

# Use a common workdir to make the cleanup easier
WORKDIR="$(mktemp -d)"

# Prepare a couple of LUKS2-encrypted disk images
#
# 1) Image with an empty password
IMAGE_EMPTY="$WORKDIR/empty.img)"
IMAGE_EMPTY_KEYFILE="$WORKDIR/empty.keyfile"
IMAGE_EMPTY_KEYFILE_ERASE="$WORKDIR/empty-erase.keyfile"
IMAGE_EMPTY_KEYFILE_ERASE_FAIL="$WORKDIR/empty-erase-fail.keyfile)"
truncate -s 32M "$IMAGE_EMPTY"
echo -n passphrase >"$IMAGE_EMPTY_KEYFILE"
chmod 0600 "$IMAGE_EMPTY_KEYFILE"
cryptsetup luksFormat --batch-mode \
                      --pbkdf pbkdf2 \
                      --pbkdf-force-iterations 1000 \
                      --use-urandom \
                      "$IMAGE_EMPTY" "$IMAGE_EMPTY_KEYFILE"
PASSWORD=passphrase NEWPASSWORD="" systemd-cryptenroll --password "$IMAGE_EMPTY"
# Duplicate the key file to test keyfile-erase as well
cp -v "$IMAGE_EMPTY_KEYFILE" "$IMAGE_EMPTY_KEYFILE_ERASE"
# The key should get erased even on a failed attempt, so test that too
cp -v "$IMAGE_EMPTY_KEYFILE" "$IMAGE_EMPTY_KEYFILE_ERASE_FAIL"

# 2) Image with a detached header and a key file offset + size
IMAGE_DETACHED="$WORKDIR/detached.img"
IMAGE_DETACHED_KEYFILE="$WORKDIR/detached.keyfile"
IMAGE_DETACHED_KEYFILE2="$WORKDIR/detached.keyfile2"
IMAGE_DETACHED_HEADER="$WORKDIR/detached.header"
truncate -s 32M "$IMAGE_DETACHED"
dd if=/dev/urandom of="$IMAGE_DETACHED_KEYFILE" count=64 bs=1
dd if=/dev/urandom of="$IMAGE_DETACHED_KEYFILE2" count=32 bs=1
chmod 0600 "$IMAGE_DETACHED_KEYFILE" "$IMAGE_DETACHED_KEYFILE2"
cryptsetup luksFormat --batch-mode \
                      --pbkdf pbkdf2 \
                      --pbkdf-force-iterations 1000 \
                      --use-urandom \
                      --header "$IMAGE_DETACHED_HEADER" \
                      --keyfile-offset 32 \
                      --keyfile-size 16 \
                      "$IMAGE_DETACHED" "$IMAGE_DETACHED_KEYFILE"
# Also, add a second key file to key slot 8
# Note: --key-slot= behaves as --new-key-slot= when used alone for backwards compatibility
cryptsetup luksAddKey --batch-mode \
                      --header "$IMAGE_DETACHED_HEADER" \
                      --key-file "$IMAGE_DETACHED_KEYFILE" \
                      --keyfile-offset 32 \
                      --keyfile-size 16 \
                      --key-slot 8 \
                      "$IMAGE_DETACHED" "$IMAGE_DETACHED_KEYFILE2"

# Prepare a couple of dummy devices we'll store a copy of the detached header
# and one of the keys on to test if systemd-cryptsetup correctly mounts them
# when necessary
STORE_IMAGE="$WORKDIR/store.img"
truncate -s 64M "$STORE_IMAGE"
STORE_LOOP="$(losetup --show --find --partscan "$STORE_IMAGE")"
sfdisk "$STORE_LOOP" <<EOF
label: gpt
type=0FC63DAF-8483-4772-8E79-3D69D8477DE4 name=header_store size=32M
type=0FC63DAF-8483-4772-8E79-3D69D8477DE4 name=keyfile_store
EOF
udevadm settle --timeout=30
mkdir -p /mnt
mkfs.ext4 -L header_store "/dev/disk/by-partlabel/header_store"
mount "/dev/disk/by-partlabel/header_store" /mnt
cp "$IMAGE_DETACHED_HEADER" /mnt/header
umount /mnt
mkfs.ext4 -L keyfile_store "/dev/disk/by-partlabel/keyfile_store"
mount "/dev/disk/by-partlabel/keyfile_store" /mnt
cp "$IMAGE_DETACHED_KEYFILE2" /mnt/keyfile
umount /mnt
udevadm settle --timeout=30

# Prepare our test crypttab
[[ -e /etc/crypttab ]] && cp -fv /etc/crypttab /tmp/crypttab.bak
cat >/etc/crypttab <<EOF
# headless should translate to headless=1
empty_key            $IMAGE_EMPTY    $IMAGE_EMPTY_KEYFILE            headless,x-systemd.device-timeout=1m
empty_key_erase      $IMAGE_EMPTY    $IMAGE_EMPTY_KEYFILE_ERASE      headless=1,keyfile-erase=1
empty_key_erase_fail $IMAGE_EMPTY    $IMAGE_EMPTY_KEYFILE_ERASE_FAIL headless=1,keyfile-erase=1,keyfile-offset=4
# Empty passphrase without try-empty-password(=yes) shouldn't work
empty_fail0          $IMAGE_EMPTY    -                               headless=1
empty_fail1          $IMAGE_EMPTY    -                               headless=1,try-empty-password=0
empty0               $IMAGE_EMPTY    -                               headless=1,try-empty-password
empty1               $IMAGE_EMPTY    -                               headless=1,try-empty-password=1
# This one expects the key to be under /{etc,run}/cryptsetup-keys.d/empty_nokey.key
empty_nokey          $IMAGE_EMPTY    -                               headless=1
empty_pkcs11_auto    $IMAGE_EMPTY    -                               headless=1,pkcs11-uri=auto

detached             $IMAGE_DETACHED $IMAGE_DETACHED_KEYFILE         headless=1,header=$IMAGE_DETACHED_HEADER,keyfile-offset=32,keyfile-size=16
detached_store0      $IMAGE_DETACHED $IMAGE_DETACHED_KEYFILE         headless=1,header=/header:LABEL=header_store,keyfile-offset=32,keyfile-size=16
detached_store1      $IMAGE_DETACHED /keyfile:LABEL=keyfile_store    headless=1,header=$IMAGE_DETACHED_HEADER
detached_store2      $IMAGE_DETACHED /keyfile:LABEL=keyfile_store    headless=1,header=/header:LABEL=header_store
detached_fail0       $IMAGE_DETACHED $IMAGE_DETACHED_KEYFILE         headless=1,header=$IMAGE_DETACHED_HEADER,keyfile-offset=32
detached_fail1       $IMAGE_DETACHED $IMAGE_DETACHED_KEYFILE         headless=1,header=$IMAGE_DETACHED_HEADER
detached_fail2       $IMAGE_DETACHED $IMAGE_DETACHED_KEYFILE         headless=1
detached_fail3       $IMAGE_DETACHED $IMAGE_DETACHED_KEYFILE         headless=1,header=$IMAGE_DETACHED_HEADER,keyfile-offset=16,keyfile-size=16
detached_fail4       $IMAGE_DETACHED $IMAGE_DETACHED_KEYFILE         headless=1,header=$IMAGE_DETACHED_HEADER,keyfile-offset=32,keyfile-size=8
detached_slot0       $IMAGE_DETACHED $IMAGE_DETACHED_KEYFILE2        headless=1,header=$IMAGE_DETACHED_HEADER
detached_slot1       $IMAGE_DETACHED $IMAGE_DETACHED_KEYFILE2        headless=1,header=$IMAGE_DETACHED_HEADER,key-slot=8
detached_slot_fail   $IMAGE_DETACHED $IMAGE_DETACHED_KEYFILE2        headless=1,header=$IMAGE_DETACHED_HEADER,key-slot=0
EOF

# Temporarily drop luks.name=/luks.uuid= from the kernel command line, as it makes
# systemd-cryptsetup-generator ignore mounts from /etc/crypttab that are not also
# specified on the kernel command line
sed -r 's/luks.(name|uuid)=[^[:space:]+]//' /proc/cmdline >/tmp/cmdline.tmp
mount --bind /tmp/cmdline.tmp /proc/cmdline
# Run the systemd-cryptsetup-generator once explicitly, to collect coverage,
# as during daemon-reload we run generators in a sandbox
mkdir -p /tmp/systemd-cryptsetup-generator.out
/usr/lib/systemd/system-generators/systemd-cryptsetup-generator /tmp/systemd-cryptsetup-generator.out/
systemctl daemon-reload
systemctl list-unit-files "systemd-cryptsetup@*"

cryptsetup_start_and_check empty_key
test -e "$IMAGE_EMPTY_KEYFILE_ERASE"
cryptsetup_start_and_check empty_key_erase
test ! -e "$IMAGE_EMPTY_KEYFILE_ERASE"
test -e "$IMAGE_EMPTY_KEYFILE_ERASE_FAIL"
cryptsetup_start_and_check -f empty_key_erase_fail
test ! -e "$IMAGE_EMPTY_KEYFILE_ERASE_FAIL"
cryptsetup_start_and_check -f empty_fail{0..1}
cryptsetup_start_and_check empty{0..1}
# First, check if we correctly fail without any key
cryptsetup_start_and_check -f empty_nokey
# And now provide the key via /{etc,run}/cryptsetup-keys.d/
mkdir -p /run/cryptsetup-keys.d
cp "$IMAGE_EMPTY_KEYFILE" /run/cryptsetup-keys.d/empty_nokey.key
cryptsetup_start_and_check empty_nokey

# Test unlocking with a PKCS#11 token
export SOFTHSM2_CONF="/etc/softhsm2.conf"
PIN="1234" systemd-cryptenroll --pkcs11-token-uri="pkcs11:token=TestToken;object=RSATestKey" --unlock-key-file="$IMAGE_EMPTY_KEYFILE" "$IMAGE_EMPTY"
cryptsetup_start_and_check empty_pkcs11_auto
cryptsetup luksKillSlot -q "$IMAGE_EMPTY" 2
cryptsetup token remove --token-id 0 "$IMAGE_EMPTY"
PIN="1234" systemd-cryptenroll --pkcs11-token-uri="pkcs11:token=TestToken;object=ECTestKey" --unlock-key-file="$IMAGE_EMPTY_KEYFILE" "$IMAGE_EMPTY"
cryptsetup_start_and_check empty_pkcs11_auto
cryptsetup luksKillSlot -q "$IMAGE_EMPTY" 2
cryptsetup token remove --token-id 0 "$IMAGE_EMPTY"

cryptsetup_start_and_check detached
cryptsetup_start_and_check detached_store{0..2}
cryptsetup_start_and_check -f detached_fail{0..4}
cryptsetup_start_and_check detached_slot{0..1}
cryptsetup_start_and_check -f detached_slot_fail

touch /testok
