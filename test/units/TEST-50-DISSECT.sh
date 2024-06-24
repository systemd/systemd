#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# Setup shared stuff & run all subtests

at_exit() {
    set +e

    if [[ -z "${IMAGE_DIR:-}" ]]; then
        return
    fi

    while read -r dir; do
        if mountpoint -q "$dir"; then
            umount -Rv "$dir"
        fi
    done < <(find "${IMAGE_DIR}" -mindepth 1 -maxdepth 1 -type d)

    rm -rf "$IMAGE_DIR"
}

trap at_exit EXIT

: "Setup base images"

export SYSTEMD_LOG_LEVEL=debug
export ARCHITECTURE
export IMAGE_DIR
export MACHINE
export MINIMAL_IMAGE
export MINIMAL_IMAGE_ROOTHASH
export OPENSSL_CONFIG
export OS_RELEASE
export ROOT_GUID
export SIGNATURE_GUID
export VERITY_GUID

machine="$(uname -m)"
if [[ "$machine" == "x86_64" ]]; then
    ROOT_GUID=4f68bce3-e8cd-4db1-96e7-fbcaf984b709
    VERITY_GUID=2c7357ed-ebd2-46d9-aec1-23d437ec2bf5
    SIGNATURE_GUID=41092b05-9fc8-4523-994f-2def0408b176
    ARCHITECTURE="x86-64"
elif [[ "$machine" =~ ^(i386|i686|x86)$ ]]; then
    ROOT_GUID=44479540-f297-41b2-9af7-d131d5f0458a
    VERITY_GUID=d13c5d3b-b5d1-422a-b29f-9454fdc89d76
    SIGNATURE_GUID=5996fc05-109c-48de-808b-23fa0830b676
    ARCHITECTURE="x86"
elif [[ "$machine" =~ ^(aarch64|aarch64_be|armv8b|armv8l)$ ]]; then
    ROOT_GUID=b921b045-1df0-41c3-af44-4c6f280d3fae
    VERITY_GUID=df3300ce-d69f-4c92-978c-9bfb0f38d820
    SIGNATURE_GUID=6db69de6-29f4-4758-a7a5-962190f00ce3
    ARCHITECTURE="arm64"
elif [[ "$machine" == "arm" ]]; then
    ROOT_GUID=69dad710-2ce4-4e3c-b16c-21a1d49abed3
    VERITY_GUID=7386cdf2-203c-47a9-a498-f2ecce45a2d6
    SIGNATURE_GUID=42b0455f-eb11-491d-98d3-56145ba9d037
    ARCHITECTURE="arm"
elif [[ "$machine" == "ia64" ]]; then
    ROOT_GUID=993d8d3d-f80e-4225-855a-9daf8ed7ea97
    VERITY_GUID=86ed10d5-b607-45bb-8957-d350f23d0571
    SIGNATURE_GUID=e98b36ee-32ba-4882-9b12-0ce14655f46a
    ARCHITECTURE="ia64"
elif [[ "$machine" == "loongarch64" ]]; then
    ROOT_GUID=77055800-792c-4f94-b39a-98c91b762bb6
    VERITY_GUID=f3393b22-e9af-4613-a948-9d3bfbd0c535
    SIGNATURE_GUID=5afb67eb-ecc8-4f85-ae8e-ac1e7c50e7d0
    ARCHITECTURE="loongarch64"
elif [[ "$machine" == "s390x" ]]; then
    ROOT_GUID=5eead9a9-fe09-4a1e-a1d7-520d00531306
    VERITY_GUID=b325bfbe-c7be-4ab8-8357-139e652d2f6b
    SIGNATURE_GUID=c80187a5-73a3-491a-901a-017c3fa953e9
    ARCHITECTURE="s390x"
elif [[ "$machine" == "ppc64le" ]]; then
    ROOT_GUID=c31c45e6-3f39-412e-80fb-4809c4980599
    VERITY_GUID=906bd944-4589-4aae-a4e4-dd983917446a
    SIGNATURE_GUID=d4a236e7-e873-4c07-bf1d-bf6cf7f1c3c6
    ARCHITECTURE="ppc64-le"
elif [[ "$machine" == "riscv64" ]]; then
    ROOT_GUID=72ec70a6-cf74-40e6-bd49-4bda08e8f224
    VERITY_GUID=b6ed5582-440b-4209-b8da-5ff7c419ea3d
    SIGNATURE_GUID=efe0f087-ea8d-4469-821a-4c2a96a8386a
    ARCHITECTURE="riscv64"
elif [[ "$machine" == "riscv32" ]]; then
    ROOT_GUID=60d5a7fe-8e7d-435c-b714-3dd8162144e1
    VERITY_GUID=ae0253be-1167-4007-ac68-43926c14c5de
    SIGNATURE_GUID=3a112a75-8729-4380-b4cf-764d79934448
    ARCHITECTURE="riscv32"
else
    echo "Unexpected uname -m: $machine in TEST-50-DISSECT.sh, please fix me"
    exit 1
fi

udevadm control --log-level=debug

IMAGE_DIR="$(mktemp -d --tmpdir="" TEST-50-IMAGES.XXX)"
cp -v /usr/share/minimal* "$IMAGE_DIR/"
MINIMAL_IMAGE="$IMAGE_DIR/minimal_0"
MINIMAL_IMAGE_ROOTHASH="$(<"$MINIMAL_IMAGE.roothash")"

install_extension_images

OS_RELEASE="$(test -e /etc/os-release && echo /etc/os-release || echo /usr/lib/os-release)"

if systemctl --version | grep -q -- +OPENSSL ; then
    # The openssl binary is installed conditionally. If we have OpenSSL support enabled and openssl is
    # missing, fail early with a proper error message.
    if ! command -v openssl &>/dev/null; then
        echo "openssl binary is missing" >/failed
        exit 1
    fi

    OPENSSL_CONFIG="$(mktemp)"
    # Unfortunately OpenSSL insists on reading some config file, hence provide one with mostly placeholder contents
    cat >"${OPENSSL_CONFIG:?}" <<EOF
[ req ]
prompt = no
distinguished_name = req_distinguished_name

[ req_distinguished_name ]
C = DE
ST = Test State
L = Test Locality
O = Org Name
OU = Org Unit Name
CN = Common Name
emailAddress = test@email.com
EOF
fi

# Make a GPT disk on the fly, with the squashfs as partition 1 and the verity hash tree as partition 2
#
# du rounds up to block size, which is more helpful for partitioning
root_size="$(du --apparent-size -k "$MINIMAL_IMAGE.raw" | cut -f1)"
verity_size="$(du --apparent-size -k "$MINIMAL_IMAGE.verity" | cut -f1)"
signature_size=4
# 4MB seems to be the minimum size blkid will accept, below that probing fails
dd if=/dev/zero of="$MINIMAL_IMAGE.gpt" bs=512 count=$((8192+root_size*2+verity_size*2+signature_size*2))
# sfdisk seems unhappy if the size overflows into the next unit, eg: 1580KiB will be interpreted as 1MiB
# so do some basic rounding up if the minimal image is more than 1 MB
if [[ "$root_size" -ge 1024 ]]; then
    root_size="$((root_size/1024 + 1))MiB"
else
    root_size="${root_size}KiB"
fi
verity_size="$((verity_size * 2))KiB"
signature_size="$((signature_size * 2))KiB"

if [[ -n "${OPENSSL_CONFIG:-}" ]]; then
    # Create key pair
    openssl req -config "$OPENSSL_CONFIG" -new -x509 -newkey rsa:1024 \
                -keyout "$MINIMAL_IMAGE.key" -out "$MINIMAL_IMAGE.crt" -days 365 -nodes
    # Sign Verity root hash with it
    openssl smime -sign -nocerts -noattr -binary \
                  -in "$MINIMAL_IMAGE.roothash" \
                  -inkey "$MINIMAL_IMAGE.key" \
                  -signer "$MINIMAL_IMAGE.crt" \
                  -outform der \
                  -out "$MINIMAL_IMAGE.roothash.p7s"
    # Generate signature partition JSON data
    echo '{"rootHash":"'"$MINIMAL_IMAGE_ROOTHASH"'","signature":"'"$(base64 -w 0 <"$MINIMAL_IMAGE.roothash.p7s")"'"}' >"$MINIMAL_IMAGE.verity-sig"
    # Pad it
    truncate -s "$signature_size" "$MINIMAL_IMAGE.verity-sig"
    # Register certificate in the (userspace) verity key ring
    mkdir -p /run/verity.d
    ln -s "$MINIMAL_IMAGE.crt" /run/verity.d/ok.crt
fi

# Construct a UUID from hash
# input:  11111111222233334444555566667777
# output: 11111111-2222-3333-4444-555566667777
uuid="$(head -c 32 "$MINIMAL_IMAGE.roothash" | sed -r 's/(.{8})(.{4})(.{4})(.{4})(.+)/\1-\2-\3-\4-\5/')"
echo -e "label: gpt\nsize=$root_size, type=$ROOT_GUID, uuid=$uuid" | sfdisk "$MINIMAL_IMAGE.gpt"
uuid="$(tail -c 32 "$MINIMAL_IMAGE.roothash" | sed -r 's/(.{8})(.{4})(.{4})(.{4})(.+)/\1-\2-\3-\4-\5/')"
echo -e "size=$verity_size, type=$VERITY_GUID, uuid=$uuid" | sfdisk "$MINIMAL_IMAGE.gpt" --append
if [[ -n "${OPENSSL_CONFIG:-}" ]]; then
    echo -e "size=$signature_size, type=$SIGNATURE_GUID" | sfdisk "$MINIMAL_IMAGE.gpt" --append
fi
sfdisk --part-label "$MINIMAL_IMAGE.gpt" 1 "Root Partition"
sfdisk --part-label "$MINIMAL_IMAGE.gpt" 2 "Verity Partition"
if [[ -n "${OPENSSL_CONFIG:-}" ]]; then
    sfdisk --part-label "$MINIMAL_IMAGE.gpt" 3 "Signature Partition"
fi
loop="$(losetup --show -P -f "$MINIMAL_IMAGE.gpt")"
partitions=(
    "${loop:?}p1"
    "${loop:?}p2"
)
if [[ -n "${OPENSSL_CONFIG:-}" ]]; then
    partitions+=("${loop:?}p3")
fi
# The kernel sometimes(?) does not emit "add" uevent for loop block partition devices.
# Let's not expect the devices to be initialized.
udevadm wait --timeout 60 --settle --initialized=no "${partitions[@]}"
udevadm lock --device="${loop}p1" dd if="$MINIMAL_IMAGE.raw" of="${loop}p1"
udevadm lock --device="${loop}p2" dd if="$MINIMAL_IMAGE.verity" of="${loop}p2"
if [[ -n "${OPENSSL_CONFIG:-}" ]]; then
    udevadm lock --device="${loop}p3" dd if="$MINIMAL_IMAGE.verity-sig" of="${loop}p3"
fi
losetup -d "$loop"
udevadm settle --timeout=60

: "Run subtests"

run_subtests

touch /testok
