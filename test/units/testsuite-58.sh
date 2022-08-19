#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

if ! command -v systemd-repart &>/dev/null; then
    echo "no systemd-repart" >/skipped
    exit 0
fi

# shellcheck source=test/units/assert.sh
. "$(dirname "$0")"/assert.sh

export SYSTEMD_LOG_LEVEL=debug
export PAGER=cat

seed=750b6cd5c4ae4012a15e7be3c29e6a47

machine="$(uname -m)"
if [ "${machine}" = "x86_64" ]; then
    root_guid=4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709
    root_uuid=60F33797-1D71-4DCB-AA6F-20564F036CD0
    usr_guid=8484680C-9521-48C6-9C11-B0720656F69E
    usr_uuid=7E3369DD-D653-4513-ADF5-B993A9F20C16
    architecture="x86-64"
elif [ "${machine}" = "i386" ] || [ "${machine}" = "i686" ] || [ "${machine}" = "x86" ]; then
    root_guid=44479540-F297-41B2-9AF7-D131D5F0458A
    root_uuid=02B4253F-29A4-404E-8972-1669D3B03C87
    usr_guid=75250D76-8CC6-458E-BD66-BD47CC81A812
    usr_uuid=7B42FFB0-B0E1-4395-B20B-C78F4A571648
    architecture="x86"
elif [ "${machine}" = "aarch64" ] || [ "${machine}" = "aarch64_be" ] || [ "${machine}" = "armv8b" ] || [ "${machine}" = "armv8l" ]; then
    root_guid=B921B045-1DF0-41C3-AF44-4C6F280D3FAE
    root_uuid=055D0227-53A6-4033-85C3-9A5973EFF483
    usr_guid=B0E01050-EE5F-4390-949A-9101B17104E9
    usr_uuid=FCE3C75E-D6A4-44C0-87F0-4C105183FB1F
    architecture="arm64"
elif [ "${machine}" = "arm" ]; then
    root_guid=69DAD710-2CE4-4E3C-B16C-21A1D49ABED3
    root_uuid=567DA89E-8DE2-4499-8D10-18F212DFF034
    usr_guid=7D0359A3-02B3-4F0A-865C-654403E70625
    usr_uuid=71E93DC2-5073-42CB-8A84-A354E64D8966
    architecture="arm"
elif [ "${machine}" = "loongarch64" ]; then
    root_guid=77055800-792C-4F94-B39A-98C91B762BB6
    root_uuid=D8EFC2D2-0133-41E4-BDCB-3B9F4CFDDDE8
    usr_guid=E611C702-575C-4CBE-9A46-434FA0BF7E3F
    usr_uuid=031FFA75-00BB-49B6-A70D-911D2D82A5B7
    architecture="loongarch64"
elif [ "${machine}" = "ia64" ]; then
    root_guid=993D8D3D-F80E-4225-855A-9DAF8ED7EA97
    root_uuid=DCF33449-0896-4EA9-BC24-7D58AEEF522D
    usr_guid=4301D2A6-4E3B-4B2A-BB94-9E0B2C4225EA
    usr_uuid=BC2BCCE7-80D6-449A-85CC-637424CE5241
    architecture="ia64"
elif [ "${machine}" = "s390x" ]; then
    root_guid=5EEAD9A9-FE09-4A1E-A1D7-520D00531306
    root_uuid=7EBE0C85-E27E-48EC-B164-F4807606232E
    usr_guid=8A4F5770-50AA-4ED3-874A-99B710DB6FEA
    usr_uuid=51171D30-35CF-4A49-B8B5-9478B9B796A5
    architecture="s390x"
elif [ "${machine}" = "ppc64le" ]; then
    root_guid=C31C45E6-3F39-412E-80FB-4809C4980599
    root_uuid=061E67A1-092F-482F-8150-B525D50D6654
    usr_guid=15BB03AF-77E7-4D4A-B12B-C0D084F7491C
    usr_uuid=C0D0823B-8040-4C7C-A629-026248E297FB
    architecture="ppc64-le"
else
    echo "Unexpected uname -m: ${machine} in testsuite-58.sh, please fix me"
    exit 1
fi

test_copy_blocks() {
    local defs imgs output

    defs="$(mktemp --directory "/tmp/test-repart.XXXXXXXXXX")"
    imgs="$(mktemp --directory "/var/tmp/test-repart.XXXXXXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -rf '$defs' '$imgs'" RETURN

    # First, create a disk image and verify its in order

    cat >"$defs/esp.conf" <<EOF
[Partition]
Type=esp
SizeMinBytes=10M
Format=vfat
EOF

    cat >"$defs/usr.conf" <<EOF
[Partition]
Type=usr-${architecture}
SizeMinBytes=10M
Format=ext4
ReadOnly=yes
EOF

    cat >"$defs/root.conf" <<EOF
[Partition]
Type=root-${architecture}
SizeMinBytes=10M
Format=ext4
MakeDirectories=/usr /efi
EOF

    systemd-repart --definitions="$defs" \
                   --empty=create \
                   --size=auto \
                   --seed="$seed" \
                   "$imgs/zzz"

    output=$(sfdisk --dump "$imgs/zzz")

    assert_in "$imgs/zzz1 : start=        2048, size=       20480, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, uuid=39107B09-615D-48FB-BA37-C663885FCE67, name=\"esp\"" "$output"
    assert_in "$imgs/zzz2 : start=       22528, size=       20480, type=${root_guid}, uuid=${root_uuid}, name=\"root-${architecture}\", attrs=\"GUID:59\"" "$output"
    assert_in "$imgs/zzz3 : start=       43008, size=       20480, type=${usr_guid}, uuid=${usr_uuid}, name=\"usr-${architecture}\", attrs=\"GUID:60\"" "$output"

    # Then, create another image with CopyBlocks=auto

    cat >"$defs/esp.conf" <<EOF
[Partition]
Type=esp
CopyBlocks=auto
EOF

    cat >"$defs/usr.conf" <<EOF
[Partition]
Type=usr-${architecture}
ReadOnly=yes
CopyBlocks=auto
EOF

    cat >"$defs/root.conf" <<EOF
[Partition]
Type=root-${architecture}
CopyBlocks=auto
EOF

    systemd-repart --definitions="$defs" \
                   --empty=create \
                   --size=auto \
                   --seed="$seed" \
                   --image="$imgs/zzz" \
                   "$imgs/yyy"

    cmp "$imgs/zzz" "$imgs/yyy"
}

test_unaligned_partition() {
    local defs imgs output

    defs="$(mktemp --directory "/tmp/test-repart.XXXXXXXXXX")"
    imgs="$(mktemp --directory "/var/tmp/test-repart.XXXXXXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -rf '$defs' '$imgs'" RETURN

    # Operate on an image with unaligned partition.

    cat >"$defs/root.conf" <<EOF
[Partition]
Type=root-${architecture}
EOF

    truncate -s 10g "$imgs/unaligned"
    sfdisk "$imgs/unaligned" <<EOF
label: gpt

start=2048, size=69044
start=71092, size=3591848
EOF

    systemd-repart --definitions="$defs" \
                   --seed="$seed" \
                   --dry-run=no \
                   "$imgs/unaligned"

    output=$(sfdisk --dump "$imgs/unaligned")

    assert_in "$imgs/unaligned1 : start=        2048, size=       69044," "$output"
    assert_in "$imgs/unaligned2 : start=       71092, size=     3591848," "$output"
    assert_in "$imgs/unaligned3 : start=     3662944, size=    17308536, type=${root_guid}, uuid=${root_uuid}, name=\"root-${architecture}\", attrs=\"GUID:59\"" "$output"
}

test_issue_21817() {
    local defs imgs output

    # testcase for #21817

    defs="$(mktemp --directory "/tmp/test-repart.XXXXXXXXXX")"
    imgs="$(mktemp --directory "/var/tmp/test-repart.XXXXXXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -rf '$defs' '$imgs'" RETURN

    cat >"$defs/test.conf" <<EOF
[Partition]
Type=root
EOF

    truncate -s 100m "$imgs/21817.img"
    sfdisk "$imgs/21817.img" <<EOF
label: gpt

size=50M, type=${root_guid}
,
EOF

    systemd-repart --pretty=yes \
                   --definitions "$imgs" \
                   --seed="$seed" \
                   --dry-run=no \
                   "$imgs/21817.img"

    output=$(sfdisk --dump "$imgs/21817.img")

    assert_in "$imgs/21817.img1 : start=        2048, size=      102400, type=${root_guid}," "$output"
    # Accept both unpadded (pre-v2.38 util-linux) and padded (v2.38+ util-linux) sizes
    assert_in "$imgs/21817.img2 : start=      104448, size=      (100319| 98304)," "$output"
}

test_sector() {
    local defs imgs output loop
    local start size ratio
    local sector="${1?}"

    defs="$(mktemp --directory "/tmp/test-repart.XXXXXXXXXX")"
    imgs="$(mktemp --directory "/var/tmp/test-repart.XXXXXXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -rf '$defs' '$imgs'" RETURN

    cat > "$defs/a.conf" <<EOF
[Partition]
Type=root
SizeMaxBytes=15M
SizeMinBytes=15M
EOF
    cat > "$defs/b.conf" <<EOF
[Partition]
Type=linux-generic
Weight=250
EOF

    cat > "$defs/c.conf" <<EOF
[Partition]
Type=linux-generic
Weight=750
EOF

    truncate -s 100m "$imgs/$sector.img"
    loop=$(losetup -b "$sector" -P --show -f "$imgs/$sector.img" )
    udevadm wait --timeout 60 --settle "${loop:?}"
    systemd-repart --pretty=yes \
                   --definitions="$defs" \
                   --seed="$seed" \
                   --empty=require \
                   --dry-run=no \
                   "$loop"

    sfdisk --verify "$loop"
    output=$(sfdisk --dump "$loop")
    losetup -d "$loop"

    ratio=$(( sector / 512 ))
    start=$(( 2048 / ratio ))
    size=$(( 30720 / ratio ))
    assert_in "${loop}p1 : start= *${start}, size= *${size}, type=${root_guid}, uuid=${root_uuid}, name=\"root-${architecture}\", attrs=\"GUID:59\"" "$output"
    start=$(( start + size ))
    size=$(( 42992 / ratio ))
    assert_in "${loop}p2 : start= *${start}, size= *${size}, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, uuid=DF71F5E3-080A-4D16-824B-18591B881380, name=\"linux-generic\"" "$output"
    start=$(( start + size ))
    size=$(( 129000 / ratio ))
    assert_in "${loop}p3 : start= *${start}, size= *${size}, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, uuid=DB081670-07AE-48CA-9F5E-813D5E40B976, name=\"linux-generic-2\"" "$output"
}

test_copy_blocks
test_unaligned_partition
test_issue_21817

# Valid block sizes on the Linux block layer are >= 512 and <= PAGE_SIZE, and
# must be powers of 2. Which leaves exactly four different ones to test on
# typical hardware
test_sector 512
test_sector 1024
test_sector 2048
test_sector 4096

echo OK >/testok

exit 0
