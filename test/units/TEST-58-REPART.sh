#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2317
set -eux
set -o pipefail

if ! command -v systemd-repart >/dev/null; then
    echo "no systemd-repart" >/skipped
    exit 77
fi

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh
# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

export SYSTEMD_LOG_LEVEL=debug
export PAGER=cat

# Disable use of special glyphs such as →
export SYSTEMD_UTF8=0

# Sanitizer runs are significantly slower, so give udevadm wait 3 times longer timeouts
if [[ -v ASAN_OPTIONS || -v UBSAN_OPTIONS ]]; then
    UDEVADM_WAIT_TIMEOUT=180
else
    UDEVADM_WAIT_TIMEOUT=60
fi

seed=750b6cd5c4ae4012a15e7be3c29e6a47

esp_guid=C12A7328-F81F-11D2-BA4B-00A0C93EC93B
xbootldr_guid=BC13C2FF-59E6-4262-A352-B275FD6F7172

machine="$(uname -m)"
if [ "${machine}" = "x86_64" ]; then
    root_guid=4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709
    root_uuid=60F33797-1D71-4DCB-AA6F-20564F036CD0
    root_uuid2=73A4CCD2-EAF5-44DA-A366-F99188210FDC
    usr_guid=8484680C-9521-48C6-9C11-B0720656F69E
    usr_uuid=7E3369DD-D653-4513-ADF5-B993A9F20C16
    architecture="x86-64"
elif [ "${machine}" = "i386" ] || [ "${machine}" = "i686" ] || [ "${machine}" = "x86" ]; then
    root_guid=44479540-F297-41B2-9AF7-D131D5F0458A
    root_uuid=02B4253F-29A4-404E-8972-1669D3B03C87
    root_uuid2=268E0FD3-B468-4806-A823-E533FE9BB9CC
    usr_guid=75250D76-8CC6-458E-BD66-BD47CC81A812
    usr_uuid=7B42FFB0-B0E1-4395-B20B-C78F4A571648
    architecture="x86"
elif [ "${machine}" = "aarch64" ] || [ "${machine}" = "aarch64_be" ] || [ "${machine}" = "armv8b" ] || [ "${machine}" = "armv8l" ]; then
    root_guid=B921B045-1DF0-41C3-AF44-4C6F280D3FAE
    root_uuid=055D0227-53A6-4033-85C3-9A5973EFF483
    root_uuid2=F7DBBE48-8FD0-4833-8411-AA34E7C8E60A
    usr_guid=B0E01050-EE5F-4390-949A-9101B17104E9
    usr_uuid=FCE3C75E-D6A4-44C0-87F0-4C105183FB1F
    architecture="arm64"
elif [ "${machine}" = "arm" ]; then
    root_guid=69DAD710-2CE4-4E3C-B16C-21A1D49ABED3
    root_uuid=567DA89E-8DE2-4499-8D10-18F212DFF034
    root_uuid2=813ECFE5-4C89-4193-8A52-437493F2F96E
    usr_guid=7D0359A3-02B3-4F0A-865C-654403E70625
    usr_uuid=71E93DC2-5073-42CB-8A84-A354E64D8966
    architecture="arm"
elif [ "${machine}" = "loongarch64" ]; then
    root_guid=77055800-792C-4F94-B39A-98C91B762BB6
    root_uuid=D8EFC2D2-0133-41E4-BDCB-3B9F4CFDDDE8
    root_uuid2=36499F9E-0688-40C1-A746-EA8FD9543C56
    usr_guid=E611C702-575C-4CBE-9A46-434FA0BF7E3F
    usr_uuid=031FFA75-00BB-49B6-A70D-911D2D82A5B7
    architecture="loongarch64"
elif [ "${machine}" = "ia64" ]; then
    root_guid=993D8D3D-F80E-4225-855A-9DAF8ED7EA97
    root_uuid=DCF33449-0896-4EA9-BC24-7D58AEEF522D
    root_uuid2=C2A6CAB7-ABEA-4FBA-8C48-CB4C52E6CA38
    usr_guid=4301D2A6-4E3B-4B2A-BB94-9E0B2C4225EA
    usr_uuid=BC2BCCE7-80D6-449A-85CC-637424CE5241
    architecture="ia64"
elif [ "${machine}" = "s390x" ]; then
    root_guid=5EEAD9A9-FE09-4A1E-A1D7-520D00531306
    root_uuid=7EBE0C85-E27E-48EC-B164-F4807606232E
    root_uuid2=2A074E1C-2A19-4094-A0C2-24B1A5D52FCB
    usr_guid=8A4F5770-50AA-4ED3-874A-99B710DB6FEA
    usr_uuid=51171D30-35CF-4A49-B8B5-9478B9B796A5
    architecture="s390x"
elif [ "${machine}" = "ppc64le" ]; then
    root_guid=C31C45E6-3F39-412E-80FB-4809C4980599
    root_uuid=061E67A1-092F-482F-8150-B525D50D6654
    root_uuid2=A6687CEF-4E4F-44E7-90B3-CDA52EA81739
    usr_guid=15BB03AF-77E7-4D4A-B12B-C0D084F7491C
    usr_uuid=C0D0823B-8040-4C7C-A629-026248E297FB
    architecture="ppc64-le"
else
    echo "Unexpected uname -m: ${machine} in TEST-58-REPART.sh, please fix me"
    exit 1
fi

testcase_basic() {
    local defs imgs output
    local loop volume

    defs="$(mktemp --directory "/tmp/test-repart.defs.XXXXXXXXXX")"
    imgs="$(mktemp --directory "/var/tmp/test-repart.imgs.XXXXXXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -rf '$defs' '$imgs'" RETURN
    chmod 0755 "$defs"

    echo "*** 1. create an empty image ***"

    systemd-repart --offline="$OFFLINE" \
                   --empty=create \
                   --size=1G \
                   --seed="$seed" \
                   "$imgs/zzz"

    output=$(sfdisk -d "$imgs/zzz" | grep -v -e 'sector-size' -e '^$')

    assert_eq "$output" "label: gpt
label-id: 1D2CE291-7CCE-4F7D-BC83-FDB49AD74EBD
device: $imgs/zzz
unit: sectors
first-lba: 2048
last-lba: 2097118"

    echo "*** 2. Testing with root, root2, home, and swap ***"

    tee "$defs/root.conf" <<EOF
[Partition]
Type=root
Format=vfat
EOF

    ln -s root.conf "$defs/root2.conf"

    tee "$defs/home.conf" <<EOF
[Partition]
Type=home
Label=home-first
Label=home-always-too-long-xxxxxxxxxxxxxx-%v
Format=vfat
EOF

    tee "$defs/swap.conf" <<EOF
[Partition]
Type=swap
SizeMaxBytes=64M
PaddingMinBytes=92M
EOF

    systemd-repart --definitions="$defs" \
                   --dry-run=yes \
                   --seed="$seed" \
                   --include-partitions=home,swap \
                   "-"

    systemd-repart --offline="$OFFLINE" \
                   --definitions="$defs" \
                   --dry-run=no \
                   --seed="$seed" \
                   --include-partitions=home,swap \
                   --offline="$OFFLINE" \
                   "$imgs/zzz"

    output=$(sfdisk -d "$imgs/zzz" | grep -v -e 'sector-size' -e '^$')

    assert_eq "$output" "label: gpt
label-id: 1D2CE291-7CCE-4F7D-BC83-FDB49AD74EBD
device: $imgs/zzz
unit: sectors
first-lba: 2048
last-lba: 2097118
$imgs/zzz1 : start=        2048, size=     1775576, type=933AC7E1-2EB4-4F13-B844-0E14E2AEF915, uuid=4980595D-D74A-483A-AA9E-9903879A0EE5, name=\"home-first\", attrs=\"GUID:59\"
$imgs/zzz2 : start=     1777624, size=      131072, type=0657FD6D-A4AB-43C4-84E5-0933C84B4F4F, uuid=78C92DB8-3D2B-4823-B0DC-792B78F66F1E, name=\"swap\""

    systemd-repart --offline="$OFFLINE" \
                   --definitions="$defs" \
                   --empty=create \
                   --size=50M \
                   --seed="$seed" \
                   --include-partitions=root,home \
                   "$imgs/qqq"

    sfdisk -d "$imgs/qqq" | grep -v -e 'sector-size' -e '^$'

    systemd-repart --offline="$OFFLINE" \
                   --empty=create \
                   --size=1G \
                   --dry-run=no \
                   --seed="$seed" \
                   --definitions "" \
                   --copy-from="$imgs/qqq" \
                   --copy-from="$imgs/qqq" \
                   "$imgs/copy"

    output=$(sfdisk -d "$imgs/copy" | grep -v -e 'sector-size' -e '^$')

    assert_eq "$output" "label: gpt
label-id: 1D2CE291-7CCE-4F7D-BC83-FDB49AD74EBD
device: $imgs/copy
unit: sectors
first-lba: 2048
last-lba: 2097118
$imgs/copy1 : start=        2048, size=       33432, type=933AC7E1-2EB4-4F13-B844-0E14E2AEF915, uuid=4980595D-D74A-483A-AA9E-9903879A0EE5, name=\"home-first\", attrs=\"GUID:59\"
$imgs/copy2 : start=       35480, size=       33440, type=${root_guid}, uuid=${root_uuid}, name=\"root-${architecture}\", attrs=\"GUID:59\"
$imgs/copy3 : start=       68920, size=       33440, type=${root_guid}, uuid=${root_uuid2}, name=\"root-${architecture}-2\", attrs=\"GUID:59\"
$imgs/copy4 : start=      102360, size=       33432, type=933AC7E1-2EB4-4F13-B844-0E14E2AEF915, uuid=4980595D-D74A-483A-AA9E-9903879A0EE5, name=\"home-first\", attrs=\"GUID:59\"
$imgs/copy5 : start=      135792, size=       33440, type=${root_guid}, uuid=${root_uuid}, name=\"root-${architecture}\", attrs=\"GUID:59\"
$imgs/copy6 : start=      169232, size=       33440, type=${root_guid}, uuid=${root_uuid2}, name=\"root-${architecture}-2\", attrs=\"GUID:59\""

    rm "$imgs/qqq" "$imgs/copy" # Save disk space

    systemd-repart --offline="$OFFLINE" \
                   --definitions="$defs" \
                   --dry-run=no \
                   --seed="$seed" \
                   --empty=force \
                   --defer-partitions=home,root \
                   "$imgs/zzz"

    output=$(sfdisk -d "$imgs/zzz" | grep -v -e 'sector-size' -e '^$')

    assert_eq "$output" "label: gpt
label-id: 1D2CE291-7CCE-4F7D-BC83-FDB49AD74EBD
device: $imgs/zzz
unit: sectors
first-lba: 2048
last-lba: 2097118
$imgs/zzz4 : start=     1777624, size=      131072, type=0657FD6D-A4AB-43C4-84E5-0933C84B4F4F, uuid=78C92DB8-3D2B-4823-B0DC-792B78F66F1E, name=\"swap\""

    systemd-repart --offline="$OFFLINE" \
                   --definitions="$defs" \
                   --dry-run=no \
                   --seed="$seed" \
                   "$imgs/zzz"

    output=$(sfdisk -d "$imgs/zzz" | grep -v -e 'sector-size' -e '^$')

    assert_eq "$output" "label: gpt
label-id: 1D2CE291-7CCE-4F7D-BC83-FDB49AD74EBD
device: $imgs/zzz
unit: sectors
first-lba: 2048
last-lba: 2097118
$imgs/zzz1 : start=        2048, size=      591856, type=933AC7E1-2EB4-4F13-B844-0E14E2AEF915, uuid=4980595D-D74A-483A-AA9E-9903879A0EE5, name=\"home-first\", attrs=\"GUID:59\"
$imgs/zzz2 : start=      593904, size=      591856, type=${root_guid}, uuid=${root_uuid}, name=\"root-${architecture}\", attrs=\"GUID:59\"
$imgs/zzz3 : start=     1185760, size=      591864, type=${root_guid}, uuid=${root_uuid2}, name=\"root-${architecture}-2\", attrs=\"GUID:59\"
$imgs/zzz4 : start=     1777624, size=      131072, type=0657FD6D-A4AB-43C4-84E5-0933C84B4F4F, uuid=78C92DB8-3D2B-4823-B0DC-792B78F66F1E, name=\"swap\""

    echo "*** 3. Testing with root, root2, home, swap, and another partition ***"

    tee "$defs/swap.conf" <<EOF
[Partition]
Type=swap
SizeMaxBytes=64M
EOF

    tee "$defs/extra.conf" <<EOF
[Partition]
Type=linux-generic
Label=custom_label
UUID=a0a1a2a3a4a5a6a7a8a9aaabacadaeaf
EOF

    echo "Label=ignored_label" >>"$defs/home.conf"
    echo "UUID=b0b1b2b3b4b5b6b7b8b9babbbcbdbebf" >>"$defs/home.conf"

    systemd-repart --offline="$OFFLINE" \
                   --definitions="$defs" \
                   --dry-run=no \
                   --seed="$seed" \
                   "$imgs/zzz"

    output=$(sfdisk -d "$imgs/zzz" | grep -v -e 'sector-size' -e '^$')

    assert_eq "$output" "label: gpt
label-id: 1D2CE291-7CCE-4F7D-BC83-FDB49AD74EBD
device: $imgs/zzz
unit: sectors
first-lba: 2048
last-lba: 2097118
$imgs/zzz1 : start=        2048, size=      591856, type=933AC7E1-2EB4-4F13-B844-0E14E2AEF915, uuid=4980595D-D74A-483A-AA9E-9903879A0EE5, name=\"home-first\", attrs=\"GUID:59\"
$imgs/zzz2 : start=      593904, size=      591856, type=${root_guid}, uuid=${root_uuid}, name=\"root-${architecture}\", attrs=\"GUID:59\"
$imgs/zzz3 : start=     1185760, size=      591864, type=${root_guid}, uuid=${root_uuid2}, name=\"root-${architecture}-2\", attrs=\"GUID:59\"
$imgs/zzz4 : start=     1777624, size=      131072, type=0657FD6D-A4AB-43C4-84E5-0933C84B4F4F, uuid=78C92DB8-3D2B-4823-B0DC-792B78F66F1E, name=\"swap\"
$imgs/zzz5 : start=     1908696, size=      188416, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, uuid=A0A1A2A3-A4A5-A6A7-A8A9-AAABACADAEAF, name=\"custom_label\""

    echo "*** 4. Resizing to 2G ***"

    systemd-repart --offline="$OFFLINE" \
                   --definitions="$defs" \
                   --size=2G \
                   --dry-run=no \
                   --seed="$seed" \
                   "$imgs/zzz"

    output=$(sfdisk -d "$imgs/zzz" | grep -v -e 'sector-size' -e '^$')

    assert_eq "$output" "label: gpt
label-id: 1D2CE291-7CCE-4F7D-BC83-FDB49AD74EBD
device: $imgs/zzz
unit: sectors
first-lba: 2048
last-lba: 4194270
$imgs/zzz1 : start=        2048, size=      591856, type=933AC7E1-2EB4-4F13-B844-0E14E2AEF915, uuid=4980595D-D74A-483A-AA9E-9903879A0EE5, name=\"home-first\", attrs=\"GUID:59\"
$imgs/zzz2 : start=      593904, size=      591856, type=${root_guid}, uuid=${root_uuid}, name=\"root-${architecture}\", attrs=\"GUID:59\"
$imgs/zzz3 : start=     1185760, size=      591864, type=${root_guid}, uuid=${root_uuid2}, name=\"root-${architecture}-2\", attrs=\"GUID:59\"
$imgs/zzz4 : start=     1777624, size=      131072, type=0657FD6D-A4AB-43C4-84E5-0933C84B4F4F, uuid=78C92DB8-3D2B-4823-B0DC-792B78F66F1E, name=\"swap\"
$imgs/zzz5 : start=     1908696, size=     2285568, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, uuid=A0A1A2A3-A4A5-A6A7-A8A9-AAABACADAEAF, name=\"custom_label\""

    echo "*** 5. Testing with root, root2, home, swap, another partition, and partition copy ***"

    dd if=/dev/urandom of="$imgs/block-copy" bs=4096 count=10240

    tee "$defs/extra2.conf" <<EOF
[Partition]
Type=linux-generic
Label=block-copy
UUID=2a1d97e1d0a346cca26eadc643926617
CopyBlocks=$imgs/block-copy
EOF

    systemd-repart --offline="$OFFLINE" \
                   --definitions="$defs" \
                   --size=3G \
                   --dry-run=no \
                   --seed="$seed" \
                   "$imgs/zzz"

    output=$(sfdisk -d "$imgs/zzz" | grep -v -e 'sector-size' -e '^$')

    assert_eq "$output" "label: gpt
label-id: 1D2CE291-7CCE-4F7D-BC83-FDB49AD74EBD
device: $imgs/zzz
unit: sectors
first-lba: 2048
last-lba: 6291422
$imgs/zzz1 : start=        2048, size=      591856, type=933AC7E1-2EB4-4F13-B844-0E14E2AEF915, uuid=4980595D-D74A-483A-AA9E-9903879A0EE5, name=\"home-first\", attrs=\"GUID:59\"
$imgs/zzz2 : start=      593904, size=      591856, type=${root_guid}, uuid=${root_uuid}, name=\"root-${architecture}\", attrs=\"GUID:59\"
$imgs/zzz3 : start=     1185760, size=      591864, type=${root_guid}, uuid=${root_uuid2}, name=\"root-${architecture}-2\", attrs=\"GUID:59\"
$imgs/zzz4 : start=     1777624, size=      131072, type=0657FD6D-A4AB-43C4-84E5-0933C84B4F4F, uuid=78C92DB8-3D2B-4823-B0DC-792B78F66F1E, name=\"swap\"
$imgs/zzz5 : start=     1908696, size=     2285568, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, uuid=A0A1A2A3-A4A5-A6A7-A8A9-AAABACADAEAF, name=\"custom_label\"
$imgs/zzz6 : start=     4194264, size=     2097152, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, uuid=2A1D97E1-D0A3-46CC-A26E-ADC643926617, name=\"block-copy\""

    cmp --bytes=$((4096*10240)) --ignore-initial=0:$((512*4194264)) "$imgs/block-copy" "$imgs/zzz"

    echo "*** 6. Testing Format=/Encrypt=/CopyFiles= ***"

    tee "$defs/extra3.conf" <<EOF
[Partition]
Type=srv
Label=luks-format-copy
UUID=7b93d1f2-595d-4ce3-b0b9-837fbd9e63b0
Format=ext4
Encrypt=yes
CopyFiles=$defs:/def
SizeMinBytes=48M
VolumeLabel=schrupfel
EOF

    systemd-repart --offline="$OFFLINE" \
                   --definitions="$defs" \
                   --size=auto \
                   --dry-run=no \
                   --seed="$seed" \
                   "$imgs/zzz"

    output=$(sfdisk -d "$imgs/zzz" | grep -v -e 'sector-size' -e '^$')

    assert_eq "$output" "label: gpt
label-id: 1D2CE291-7CCE-4F7D-BC83-FDB49AD74EBD
device: $imgs/zzz
unit: sectors
first-lba: 2048
last-lba: 6422487
$imgs/zzz1 : start=        2048, size=      591856, type=933AC7E1-2EB4-4F13-B844-0E14E2AEF915, uuid=4980595D-D74A-483A-AA9E-9903879A0EE5, name=\"home-first\", attrs=\"GUID:59\"
$imgs/zzz2 : start=      593904, size=      591856, type=${root_guid}, uuid=${root_uuid}, name=\"root-${architecture}\", attrs=\"GUID:59\"
$imgs/zzz3 : start=     1185760, size=      591864, type=${root_guid}, uuid=${root_uuid2}, name=\"root-${architecture}-2\", attrs=\"GUID:59\"
$imgs/zzz4 : start=     1777624, size=      131072, type=0657FD6D-A4AB-43C4-84E5-0933C84B4F4F, uuid=78C92DB8-3D2B-4823-B0DC-792B78F66F1E, name=\"swap\"
$imgs/zzz5 : start=     1908696, size=     2285568, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, uuid=A0A1A2A3-A4A5-A6A7-A8A9-AAABACADAEAF, name=\"custom_label\"
$imgs/zzz6 : start=     4194264, size=     2097152, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, uuid=2A1D97E1-D0A3-46CC-A26E-ADC643926617, name=\"block-copy\"
$imgs/zzz7 : start=     6291416, size=      131072, type=3B8F8425-20E0-4F3B-907F-1A25A76F98E8, uuid=7B93D1F2-595D-4CE3-B0B9-837FBD9E63B0, name=\"luks-format-copy\", attrs=\"GUID:59\""

    if systemd-detect-virt --quiet --container; then
        echo "Skipping encrypt mount tests in container."
        return
    fi

    loop="$(losetup -P --show --find "$imgs/zzz")"
    udevadm wait --timeout="$UDEVADM_WAIT_TIMEOUT" --settle "${loop:?}p7"

    cryptsetup luksDump "${loop}p7" | grep 'Flags:[[:space:]]*allow-discards' >/dev/null

    volume="test-repart-$RANDOM"

    touch "$imgs/empty-password"
    cryptsetup open --type=luks2 --key-file="$imgs/empty-password" "${loop}p7" "$volume"
    mkdir -p "$imgs/mount"
    mount -t ext4 "/dev/mapper/$volume" "$imgs/mount"
    # Use deferred closing on the mapper and autoclear on the loop, so they are cleaned up on umount
    cryptsetup close --deferred "$volume"
    losetup -d "$loop"
    diff -r "$imgs/mount/def" "$defs" >/dev/null
    umount "$imgs/mount"

    # Validate that the VolumeLabel= had the desired effect
    PASSWORD="" systemd-dissect "$imgs/zzz" -M "$imgs/mount"
    udevadm info /dev/disk/by-label/schrupfel | grep ID_FS_TYPE=crypto_LUKS >/dev/null
    systemd-dissect -U "$imgs/mount"

    echo "*** 7. Testing Discard=no ***"

    tee "$defs/extra4.conf" <<EOF
[Partition]
Type=var
Label=luks-no-discards
UUID=329b9db2-dfd9-4f39-8ebf-53b582b05fcd
Format=ext4
Encrypt=yes
CopyFiles=$defs:/def
SizeMinBytes=48M
Discard=no
EOF

    systemd-repart --offline="$OFFLINE" \
                   --definitions="$defs" \
                   --size=auto \
                   --dry-run=no \
                   --seed="$seed" \
                   "$imgs/zzz"

    output=$(sfdisk -d "$imgs/zzz" | grep -v -e 'sector-size' -e '^$')

    assert_eq "$output" "label: gpt
label-id: 1D2CE291-7CCE-4F7D-BC83-FDB49AD74EBD
device: $imgs/zzz
unit: sectors
first-lba: 2048
last-lba: 6553559
$imgs/zzz1 : start=        2048, size=      591856, type=933AC7E1-2EB4-4F13-B844-0E14E2AEF915, uuid=4980595D-D74A-483A-AA9E-9903879A0EE5, name=\"home-first\", attrs=\"GUID:59\"
$imgs/zzz2 : start=      593904, size=      591856, type=${root_guid}, uuid=${root_uuid}, name=\"root-${architecture}\", attrs=\"GUID:59\"
$imgs/zzz3 : start=     1185760, size=      591864, type=${root_guid}, uuid=${root_uuid2}, name=\"root-${architecture}-2\", attrs=\"GUID:59\"
$imgs/zzz4 : start=     1777624, size=      131072, type=0657FD6D-A4AB-43C4-84E5-0933C84B4F4F, uuid=78C92DB8-3D2B-4823-B0DC-792B78F66F1E, name=\"swap\"
$imgs/zzz5 : start=     1908696, size=     2285568, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, uuid=A0A1A2A3-A4A5-A6A7-A8A9-AAABACADAEAF, name=\"custom_label\"
$imgs/zzz6 : start=     4194264, size=     2097152, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, uuid=2A1D97E1-D0A3-46CC-A26E-ADC643926617, name=\"block-copy\"
$imgs/zzz7 : start=     6291416, size=      131072, type=3B8F8425-20E0-4F3B-907F-1A25A76F98E8, uuid=7B93D1F2-595D-4CE3-B0B9-837FBD9E63B0, name=\"luks-format-copy\", attrs=\"GUID:59\"
$imgs/zzz8 : start=     6422488, size=      131072, type=4D21B016-B534-45C2-A9FB-5C16E091FD2D, uuid=329B9DB2-DFD9-4F39-8EBF-53B582B05FCD, name=\"luks-no-discards\", attrs=\"GUID:59\""

    loop="$(losetup -P --show --find "$imgs/zzz")"
    udevadm wait --timeout="$UDEVADM_WAIT_TIMEOUT" --settle "${loop:?}p8"

    cryptsetup luksDump "${loop}p8" | grep 'Flags:[[:space:]]*(no flags)' >/dev/null
    losetup -d "$loop"
}

testcase_copy_from_grain_padding() {
    local defs imgs output

    defs="$(mktemp --directory "/tmp/test-repart.defs.XXXXXXXXXX")"
    imgs="$(mktemp --directory "/var/tmp/test-repart.imgs.XXXXXXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -rf '$defs' '$imgs'" RETURN
    chmod 0755 "$defs"

    truncate -s 80MiB "$imgs/copy_from"
    sfdisk "$imgs/copy_from" <<EOF
label: gpt
grain: 4194304

size=40961, type=${root_guid}, uuid=837c3d67-21b3-478e-be82-7e7f83bf96d3
size=10240, type=${xbootldr_guid}, uuid=4985c03e-eecb-4fe0-9f65-3f6345782214
EOF

    output=$(sfdisk --dump "$imgs/copy_from")

    # Padding between partition 1 and 2 is 8191 sectors
    assert_in "$imgs/copy_from1 : start=        8192, size=       40961, type=${root_guid}," "$output"
    assert_in "$imgs/copy_from2 : start=       57344, size=       10240, type=${xbootldr_guid}," "$output"

    truncate -s 100MiB "$imgs/copy_to"
    output=$(systemd-repart --offline="$OFFLINE" \
                            --empty=allow \
                            --definitions="$defs" \
                            --seed="$seed" \
                            --dry-run=no \
                            --json=pretty \
                            --copy-from="$imgs/copy_from" \
                            --grain-size=512 \
                            "$imgs/copy_to")

    output=$(sfdisk --dump "$imgs/copy_to")

    assert_in "$imgs/copy_to1 : start=        2048, size=       40961, type=${root_guid}," "$output"
    # We set new grain-size to 1 sector, so padding now should be 8191 sectors again
    assert_in "$imgs/copy_to2 : start=       51200, size=       10240, type=${xbootldr_guid}," "$output"
}

testcase_copy_from_respects_new_grain() {
    local defs imgs output

    defs="$(mktemp --directory "/tmp/test-repart.defs.XXXXXXXXXX")"
    imgs="$(mktemp --directory "/var/tmp/test-repart.imgs.XXXXXXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -rf '$defs' '$imgs'" RETURN
    chmod 0755 "$defs"

    truncate -s 80MiB "$imgs/copy_from"
    sfdisk "$imgs/copy_from" <<EOF
label: gpt

size=20480, type=${root_guid}, uuid=837c3d67-21b3-478e-be82-7e7f83bf96d3
size=10240, type=${xbootldr_guid}, uuid=4985c03e-eecb-4fe0-9f65-3f6345782214
EOF

    truncate -s 100MiB "$imgs/copy_to"
    output=$(systemd-repart --offline="$OFFLINE" \
                            --empty=allow \
                            --definitions="$defs" \
                            --seed="$seed" \
                            --dry-run=no \
                            --json=pretty \
                            --copy-from="$imgs/copy_from" \
                            --grain-size=4194304 \
                            "$imgs/copy_to")

    output=$(sfdisk --dump "$imgs/copy_to")

    assert_in "$imgs/copy_to1 : start=        8192, size=       24576, type=${root_guid}," "$output"
    assert_in "$imgs/copy_to2 : start=       32768, size=       16384, type=${xbootldr_guid}," "$output"
}

testcase_copy_from_no_padding_at_beginning_and_end() {
    local defs imgs output

    defs="$(mktemp --directory "/tmp/test-repart.defs.XXXXXXXXXX")"
    imgs="$(mktemp --directory "/var/tmp/test-repart.imgs.XXXXXXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -rf '$defs' '$imgs'" RETURN
    chmod 0755 "$defs"

    tee "$defs/03-esp.conf" <<EOF
[Partition]
Type=esp
EOF

    truncate -s 80MiB "$imgs/copy_from"
    sfdisk "$imgs/copy_from" <<EOF
label: gpt

start=2280, size=20480, type=${root_guid}, uuid=837c3d67-21b3-478e-be82-7e7f83bf96d3
start=22760, size=10240, type=${xbootldr_guid}, uuid=4985c03e-eecb-4fe0-9f65-3f6345782214
EOF

    truncate -s 60MiB "$imgs/copy_to"
    output=$(systemd-repart --offline="$OFFLINE" \
                            --empty=allow \
                            --definitions="$defs" \
                            --seed="$seed" \
                            --dry-run=no \
                            --json=pretty \
                            --copy-from="$imgs/copy_from" \
                            "$imgs/copy_to")

    output=$(sfdisk --dump "$imgs/copy_to")

    assert_in "first-lba: 2048" "$output"
    assert_in "last-lba: 122846" "$output"
    assert_in "$imgs/copy_to1 : start=        2048, size=       20480, type=${root_guid}," "$output"
    assert_in "$imgs/copy_to2 : start=       22528, size=       10240, type=${xbootldr_guid}," "$output"
    assert_in "$imgs/copy_to3 : start=       32768, size=       90072, type=${esp_guid}," "$output"
}

testcase_size_auto_with_grain_size() {
    local defs imgs output

    defs="$(mktemp --directory "/tmp/test-repart.defs.XXXXXXXXXX")"
    imgs="$(mktemp --directory "/var/tmp/test-repart.imgs.XXXXXXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -rf '$defs' '$imgs'" RETURN
    chmod 0755 "$defs"

    tee "$defs/01-esp.conf" <<EOF
[Partition]
Type=esp
SizeMinBytes=10M
EOF

    tee "$defs/02-usr.conf" <<EOF
[Partition]
Type=usr-${architecture}
SizeMinBytes=10M
EOF

    tee "$defs/03-root.conf" <<EOF
[Partition]
Type=root-${architecture}
SizeMinBytes=10M
EOF

    systemd-repart --offline="$OFFLINE" \
                   --empty=create \
                   --size=auto \
                   --definitions="$defs" \
                   --seed="$seed" \
                   --dry-run=no \
                   --grain-size=2097152 \
                   "$imgs/auto"

    output=$(sfdisk --dump "$imgs/auto")

    assert_in "first-lba: 2048" "$output"
    assert_in "last-lba: 65535" "$output"
    assert_in "$imgs/auto1 : start=        4096, size=       20480, type=${esp_guid}," "$output"
    assert_in "$imgs/auto2 : start=       24576, size=       20480, type=${usr_guid}," "$output"
    assert_in "$imgs/auto3 : start=       45056, size=       20480, type=${root_guid}," "$output"
}

testcase_dropin() {
    local defs imgs output

    defs="$(mktemp --directory "/tmp/test-repart.defs.XXXXXXXXXX")"
    imgs="$(mktemp --directory "/var/tmp/test-repart.imgs.XXXXXXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -rf '$defs' '$imgs'" RETURN
    chmod 0755 "$defs"

    tee "$defs/root.conf" <<EOF
[Partition]
Type=swap
SizeMaxBytes=64M
UUID=837c3d67-21b3-478e-be82-7e7f83bf96d3
EOF

    mkdir -p "$defs/root.conf.d"
    tee "$defs/root.conf.d/override1.conf" <<EOF
[Partition]
Label=label1
SizeMaxBytes=32M
EOF

    tee "$defs/root.conf.d/override2.conf" <<EOF
[Partition]
Label=label2
EOF

    output=$(systemd-repart --offline="$OFFLINE" \
                            --definitions="$defs" \
                            --empty=create \
                            --size=100M \
                            --json=pretty \
                            "$imgs/zzz")

    diff -u - <<EOF <(echo "$output")
[
	{
		"type" : "swap",
		"label" : "label2",
		"uuid" : "837c3d67-21b3-478e-be82-7e7f83bf96d3",
		"partno" : 0,
		"file" : "$defs/root.conf",
		"node" : "$imgs/zzz1",
		"offset" : 1048576,
		"old_size" : 0,
		"raw_size" : 33554432,
		"size" : "-> 32M",
		"old_padding" : 0,
		"raw_padding" : 70234112,
		"padding" : "-> 66.9M",
		"activity" : "create",
		"drop-in_files" : [
			"$defs/root.conf.d/override1.conf",
			"$defs/root.conf.d/override2.conf"
		]
	}
]
EOF
}

testcase_multiple_definitions() {
    local defs imgs output

    defs="$(mktemp --directory "/tmp/test-repart.defs.XXXXXXXXXX")"
    imgs="$(mktemp --directory "/var/tmp/test-repart.imgs.XXXXXXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -rf '$defs' '$imgs'" RETURN
    chmod 0755 "$defs"

    mkdir -p "$defs/1"
    tee "$defs/1/root1.conf" <<EOF
[Partition]
Type=swap
SizeMaxBytes=32M
UUID=7b93d1f2-595d-4ce3-b0b9-837fbd9e63b0
Label=label1
EOF

    mkdir -p "$defs/2"
    tee "$defs/2/root2.conf" <<EOF
[Partition]
Type=swap
SizeMaxBytes=32M
UUID=837c3d67-21b3-478e-be82-7e7f83bf96d3
Label=label2
EOF

    output=$(systemd-repart --offline="$OFFLINE" \
                            --definitions="$defs/1" \
                            --definitions="$defs/2" \
                            --empty=create \
                            --size=100M \
                            --json=pretty \
                            "$imgs/zzz")

    diff -u - <<EOF <(echo "$output")
[
	{
		"type" : "swap",
		"label" : "label1",
		"uuid" : "7b93d1f2-595d-4ce3-b0b9-837fbd9e63b0",
		"partno" : 0,
		"file" : "$defs/1/root1.conf",
		"node" : "$imgs/zzz1",
		"offset" : 1048576,
		"old_size" : 0,
		"raw_size" : 33554432,
		"size" : "-> 32M",
		"old_padding" : 0,
		"raw_padding" : 0,
		"padding" : "-> 0B",
		"activity" : "create"
	},
	{
		"type" : "swap",
		"label" : "label2",
		"uuid" : "837c3d67-21b3-478e-be82-7e7f83bf96d3",
		"partno" : 1,
		"file" : "$defs/2/root2.conf",
		"node" : "$imgs/zzz2",
		"offset" : 34603008,
		"old_size" : 0,
		"raw_size" : 33554432,
		"size" : "-> 32M",
		"old_padding" : 0,
		"raw_padding" : 36679680,
		"padding" : "-> 34.9M",
		"activity" : "create"
	}
]
EOF
}

testcase_copy_blocks() {
    local defs imgs output

    defs="$(mktemp --directory "/tmp/test-repart.defs.XXXXXXXXXX")"
    imgs="$(mktemp --directory "/var/tmp/test-repart.imgs.XXXXXXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -rf '$defs' '$imgs'" RETURN
    chmod 0755 "$defs"

    echo "*** First, create a disk image and verify its in order ***"

    tee "$defs/esp.conf" <<EOF
[Partition]
Type=esp
SizeMinBytes=10M
Format=vfat
EOF

    tee "$defs/usr.conf" <<EOF
[Partition]
Type=usr-${architecture}
SizeMinBytes=10M
Format=ext4
ReadOnly=yes
EOF

    tee "$defs/root.conf" <<EOF
[Partition]
Type=root-${architecture}
SizeMinBytes=10M
Format=ext4
MakeDirectories=/usr /efi
EOF

    systemd-repart --offline="$OFFLINE" \
                   --definitions="$defs" \
                   --empty=create \
                   --size=auto \
                   --seed="$seed" \
                   "$imgs/zzz"

    output=$(sfdisk --dump "$imgs/zzz")

    assert_in "$imgs/zzz1 : start=        2048, size=      532480, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, uuid=39107B09-615D-48FB-BA37-C663885FCE67, name=\"esp\"" "$output"
    assert_in "$imgs/zzz2 : start=      534528, size=       65536, type=${root_guid}, uuid=${root_uuid}, name=\"root-${architecture}\", attrs=\"GUID:59\"" "$output"
    assert_in "$imgs/zzz3 : start=      600064, size=       65536, type=${usr_guid}, uuid=${usr_uuid}, name=\"usr-${architecture}\", attrs=\"GUID:60\"" "$output"

    if systemd-detect-virt --quiet --container; then
        echo "Skipping second part of copy blocks tests in container."
        return
    fi

    echo "*** Second, create another image with CopyBlocks=auto ***"

    tee "$defs/esp.conf" <<EOF
[Partition]
Type=esp
CopyBlocks=auto
EOF

    tee "$defs/usr.conf" <<EOF
[Partition]
Type=usr-${architecture}
ReadOnly=yes
CopyBlocks=auto
EOF

    tee "$defs/root.conf" <<EOF
[Partition]
Type=root-${architecture}
CopyBlocks=auto
EOF

    systemd-repart --offline="$OFFLINE" \
                   --definitions="$defs" \
                   --empty=create \
                   --size=auto \
                   --seed="$seed" \
                   --image="$imgs/zzz" \
                   "$imgs/yyy"

    cmp "$imgs/zzz" "$imgs/yyy"
}

testcase_unaligned_partition() {
    local defs imgs output

    defs="$(mktemp --directory "/tmp/test-repart.defs.XXXXXXXXXX")"
    imgs="$(mktemp --directory "/var/tmp/test-repart.imgs.XXXXXXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -rf '$defs' '$imgs'" RETURN
    chmod 0755 "$defs"

    echo "*** Operate on an image with unaligned partition ***"

    tee "$defs/root.conf" <<EOF
[Partition]
Type=root-${architecture}
EOF

    truncate -s 10g "$imgs/unaligned"
    sfdisk "$imgs/unaligned" <<EOF
label: gpt

start=2048, size=69044
start=71092, size=3591848
EOF

    systemd-repart --offline="$OFFLINE" \
                   --definitions="$defs" \
                   --seed="$seed" \
                   --dry-run=no \
                   "$imgs/unaligned"

    output=$(sfdisk --dump "$imgs/unaligned")

    assert_in "$imgs/unaligned1 : start=        2048, size=       69044," "$output"
    assert_in "$imgs/unaligned2 : start=       71092, size=     3591848," "$output"
    assert_in "$imgs/unaligned3 : start=     3662944, size=    17308536, type=${root_guid}, uuid=${root_uuid}, name=\"root-${architecture}\", attrs=\"GUID:59\"" "$output"
}

testcase_output_order() {
    local defs imgs output

    defs="$(mktemp --directory "/tmp/test-repart.defs.XXXXXXXXXX")"
    imgs="$(mktemp --directory "/var/tmp/test-repart.imgs.XXXXXXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -rf '$defs' '$imgs'" RETURN
    chmod 0755 "$defs"

    echo "*** Ensure the order of the partition list is correct ***"

    # make this one min size 20MiB so that it has to be assigned slot 4
    tee "$defs/01-home.conf" <<EOF
[Partition]
Type=home
SizeMinBytes=20971520
EOF

    tee "$defs/02-swap.conf" <<EOF
[Partition]
Type=swap
EOF

    tee "$defs/03-esp.conf" <<EOF
[Partition]
Type=esp
EOF

    tee "$defs/04-root.conf" <<EOF
[Partition]
Type=root-${architecture}
EOF

    truncate -s 80MiB "$imgs/order"
    sfdisk "$imgs/order" <<EOF
label: gpt

size=10M, type=${root_guid}, uuid=837c3d67-21b3-478e-be82-7e7f83bf96d3
size=5M, type=${xbootldr_guid}, uuid=4985c03e-eecb-4fe0-9f65-3f6345782214
start=30M, size=10M, type=${esp_guid}, uuid=91c30bc9-0187-4db6-81a2-c648294197f8
EOF

    output=$(systemd-repart --offline="$OFFLINE" \
                            --definitions="$defs" \
                            --seed="$seed" \
                            --dry-run=no \
                            --json=pretty \
                            "$imgs/order")

    diff -u - <<EOF <(echo "$output")
[
	{
		"type" : "root-$architecture",
		"label" : "root-$architecture",
		"uuid" : "837c3d67-21b3-478e-be82-7e7f83bf96d3",
		"partno" : 0,
		"file" : "$defs/04-root.conf",
		"node" : "$imgs/order1",
		"offset" : 1048576,
		"old_size" : 10485760,
		"raw_size" : 10485760,
		"size" : "10M",
		"old_padding" : 0,
		"raw_padding" : 0,
		"padding" : "0B",
		"activity" : "unchanged"
	},
	{
		"type" : "xbootldr",
		"label" : "xbootldr",
		"uuid" : "4985c03e-eecb-4fe0-9f65-3f6345782214",
		"partno" : 1,
		"file" : null,
		"node" : "$imgs/order2",
		"offset" : 11534336,
		"old_size" : 5242880,
		"raw_size" : 5242880,
		"size" : "5M",
		"old_padding" : 14680064,
		"raw_padding" : 0,
		"padding" : "14M -> 0B",
		"activity" : "unchanged"
	},
	{
		"type" : "swap",
		"label" : "swap",
		"uuid" : "78c92db8-3d2b-4823-b0dc-792b78f66f1e",
		"partno" : 3,
		"file" : "$defs/02-swap.conf",
		"node" : "$imgs/order4",
		"offset" : 16777216,
		"old_size" : 0,
		"raw_size" : 14680064,
		"size" : "-> 14M",
		"old_padding" : 0,
		"raw_padding" : 0,
		"padding" : "-> 0B",
		"activity" : "create"
	},
	{
		"type" : "esp",
		"label" : "esp",
		"uuid" : "91c30bc9-0187-4db6-81a2-c648294197f8",
		"partno" : 2,
		"file" : "$defs/03-esp.conf",
		"node" : "$imgs/order3",
		"offset" : 31457280,
		"old_size" : 10485760,
		"raw_size" : 26202112,
		"size" : "10M -> 24.9M",
		"old_padding" : 41922560,
		"raw_padding" : 0,
		"padding" : "39.9M -> 0B",
		"activity" : "resize"
	},
	{
		"type" : "home",
		"label" : "home",
		"uuid" : "4980595d-d74a-483a-aa9e-9903879a0ee5",
		"partno" : 4,
		"file" : "$defs/01-home.conf",
		"node" : "$imgs/order5",
		"offset" : 57659392,
		"old_size" : 0,
		"raw_size" : 26206208,
		"size" : "-> 24.9M",
		"old_padding" : 0,
		"raw_padding" : 0,
		"padding" : "-> 0B",
		"activity" : "create"
	}
]
EOF

    output=$(sfdisk --dump "$imgs/order")

    assert_in "$imgs/order1 : start=        2048, size=       20480, type=${root_guid}," "$output"
    assert_in "$imgs/order2 : start=       22528, size=       10240, type=${xbootldr_guid}," "$output"
    assert_in "$imgs/order3 : start=       61440, size=       51176, type=${esp_guid}," "$output"
    assert_in "$imgs/order4 : start=       32768, size=       28672, type=0657FD6D-A4AB-43C4-84E5-0933C84B4F4F," "$output"
    assert_in "$imgs/order5 : start=      112616, size=       51184, type=933AC7E1-2EB4-4F13-B844-0E14E2AEF915," "$output"
}

testcase_issue_21817() {
    local defs imgs output

    defs="$(mktemp --directory "/tmp/test-repart.defs.XXXXXXXXXX")"
    imgs="$(mktemp --directory "/var/tmp/test-repart.imgs.XXXXXXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -rf '$defs' '$imgs'" RETURN
    chmod 0755 "$defs"

    echo "*** testcase for #21817 ***"

    tee "$defs/test.conf" <<EOF
[Partition]
Type=root
EOF

    truncate -s 100m "$imgs/21817.img"
    sfdisk "$imgs/21817.img" <<EOF
label: gpt

size=50M, type=${root_guid}
,
EOF

    systemd-repart --offline="$OFFLINE" \
                   --pretty=yes \
                   --definitions "$imgs" \
                   --seed="$seed" \
                   --dry-run=no \
                   "$imgs/21817.img"

    output=$(sfdisk --dump "$imgs/21817.img")

    assert_in "$imgs/21817.img1 : start=        2048, size=      102400, type=${root_guid}," "$output"
    # Accept both unpadded (pre-v2.38 util-linux) and padded (v2.38+ util-linux) sizes
    assert_in "$imgs/21817.img2 : start=      104448, size=      (100319| 98304)," "$output"
}

testcase_issue_24553() {
    local defs imgs output

    defs="$(mktemp --directory "/tmp/test-repart.defs.XXXXXXXXXX")"
    imgs="$(mktemp --directory "/var/tmp/test-repart.imgs.XXXXXXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -rf '$defs' '$imgs'" RETURN
    chmod 0755 "$defs"

    echo "*** testcase for #24553 ***"

    tee "$defs/root.conf" <<EOF
[Partition]
Type=root
SizeMinBytes=10G
SizeMaxBytes=120G
EOF

    tee "$imgs/partscript" <<EOF
label: gpt
label-id: C9FFE979-A415-C449-B729-78C7AA664B10
unit: sectors
first-lba: 40

start=40, size=524288, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, uuid=F2E89C8A-DC5D-4C4C-A29C-6CFB643B74FD, name="ESP System Partition"
start=524328, size=14848000, type=${root_guid}, uuid=${root_uuid}, name="root-${architecture}"
EOF

    echo "*** 1. Operate on a small image compared with SizeMinBytes= ***"
    truncate -s 8g "$imgs/zzz"
    sfdisk "$imgs/zzz" <"$imgs/partscript"

    # This should fail, but not trigger assertions.
    assert_rc 1 systemd-repart --offline="$OFFLINE" \
                               --definitions="$defs" \
                               --seed="$seed" \
                               --dry-run=no \
                               "$imgs/zzz"

    output=$(sfdisk --dump "$imgs/zzz")
    assert_in "$imgs/zzz2 : start=      524328, size=    14848000, type=${root_guid}, uuid=${root_uuid}, name=\"root-${architecture}\"" "$output"

    echo "*** 2. Operate on an larger image compared with SizeMinBytes= ***"
    rm -f "$imgs/zzz"
    truncate -s 12g "$imgs/zzz"
    sfdisk "$imgs/zzz" <"$imgs/partscript"

    # This should succeed.
    systemd-repart --offline="$OFFLINE" \
                   --definitions="$defs" \
                   --seed="$seed" \
                   --dry-run=no \
                   "$imgs/zzz"

    output=$(sfdisk --dump "$imgs/zzz")
    assert_in "$imgs/zzz2 : start=      524328, size=    24641456, type=${root_guid}, uuid=${root_uuid}, name=\"root-${architecture}\"" "$output"

    echo "*** 3. Multiple partitions with Priority= (small disk) ***"
    tee "$defs/root.conf" <<EOF
[Partition]
Type=root
SizeMinBytes=10G
SizeMaxBytes=120G
Priority=100
EOF

    tee "$defs/usr.conf" <<EOF
[Partition]
Type=usr
SizeMinBytes=10M
Priority=10
EOF

    rm -f "$imgs/zzz"
    truncate -s 8g "$imgs/zzz"
    sfdisk "$imgs/zzz" <"$imgs/partscript"

    # This should also succeed, but root is not extended.
    systemd-repart --offline="$OFFLINE" \
                   --definitions="$defs" \
                   --seed="$seed" \
                   --dry-run=no \
                   "$imgs/zzz"

    output=$(sfdisk --dump "$imgs/zzz")
    assert_in "$imgs/zzz2 : start=      524328, size=    14848000, type=${root_guid}, uuid=${root_uuid}, name=\"root-${architecture}\"" "$output"
    assert_in "$imgs/zzz3 : start=    15372328, size=     1404848, type=${usr_guid}, uuid=${usr_uuid}, name=\"usr-${architecture}\", attrs=\"GUID:59\"" "$output"

    echo "*** 4. Multiple partitions with Priority= (large disk) ***"
    rm -f "$imgs/zzz"
    truncate -s 12g "$imgs/zzz"
    sfdisk "$imgs/zzz" <"$imgs/partscript"

    # This should also succeed, and root is extended.
    systemd-repart --offline="$OFFLINE" \
                   --definitions="$defs" \
                   --seed="$seed" \
                   --dry-run=no \
                   "$imgs/zzz"

    output=$(sfdisk --dump "$imgs/zzz")
    assert_in "$imgs/zzz2 : start=      524328, size=    20971520, type=${root_guid}, uuid=${root_uuid}, name=\"root-${architecture}\"" "$output"
    assert_in "$imgs/zzz3 : start=    21495848, size=     3669936, type=${usr_guid}, uuid=${usr_uuid}, name=\"usr-${architecture}\", attrs=\"GUID:59\"" "$output"
}

testcase_zero_uuid() {
    local defs imgs output

    defs="$(mktemp --directory "/tmp/test-repart.defs.XXXXXXXXXX")"
    imgs="$(mktemp --directory "/var/tmp/test-repart.imgs.XXXXXXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -rf '$defs' '$imgs'" RETURN
    chmod 0755 "$defs"

    echo "*** Test image with zero UUID ***"

    tee "$defs/root.conf" <<EOF
[Partition]
Type=root-${architecture}
UUID=null
EOF

    systemd-repart --offline="$OFFLINE" \
                   --definitions="$defs" \
                   --seed="$seed" \
                   --dry-run=no \
                   --empty=create \
                   --size=auto \
                   "$imgs/zero"

    output=$(sfdisk --dump "$imgs/zero")

    assert_in "$imgs/zero1 : start=        2048, size=       20480, type=${root_guid}, uuid=00000000-0000-0000-0000-000000000000" "$output"
}

testcase_verity() {
    local defs imgs output

    defs="$(mktemp --directory "/tmp/test-repart.defs.XXXXXXXXXX")"
    imgs="$(mktemp --directory "/var/tmp/test-repart.imgs.XXXXXXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -rf '$defs' '$imgs'" RETURN
    chmod 0755 "$defs"

    echo "*** dm-verity ***"

    tee "$defs/verity-data.conf" <<EOF
[Partition]
Type=root-${architecture}
CopyFiles=${defs}
Verity=data
VerityMatchKey=root
Minimize=guess
EOF

    tee "$defs/verity-hash.conf" <<EOF
[Partition]
Type=root-${architecture}-verity
Verity=hash
VerityMatchKey=root
Minimize=yes
EOF

    tee "$defs/verity-sig.conf" <<EOF
[Partition]
Type=root-${architecture}-verity-sig
Verity=signature
VerityMatchKey=root
EOF

    # Unfortunately OpenSSL insists on reading some config file, hence provide one with mostly placeholder contents
    tee >"$defs/verity.openssl.cnf" <<EOF
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

    openssl req \
            -config "$defs/verity.openssl.cnf" \
            -new -x509 \
            -newkey rsa:1024 \
            -keyout "$defs/verity.key" \
            -out "$defs/verity.crt" \
            -days 365 \
            -nodes

    mkdir -p /run/verity.d
    ln -sf "$defs/verity.crt" /run/verity.d/ok.crt

    output=$(systemd-repart --offline="$OFFLINE" \
                            --definitions="$defs" \
                            --seed="$seed" \
                            --dry-run=no \
                            --empty=create \
                            --size=auto \
                            --split=yes \
                            --json=pretty \
                            --private-key="$defs/verity.key" \
                            --certificate="$defs/verity.crt" \
                            "$imgs/verity")

    drh=$(jq -r ".[] | select(.type == \"root-${architecture}\") | .roothash" <<<"$output")
    hrh=$(jq -r ".[] | select(.type == \"root-${architecture}-verity\") | .roothash" <<<"$output")
    srh=$(jq -r ".[] | select(.type == \"root-${architecture}-verity-sig\") | .roothash" <<<"$output")

    assert_eq "$drh" "$hrh"
    assert_eq "$hrh" "$srh"

    # The split-out verity signature file should be a valid JSON document (i.e. trailing NUL padding
    # from the on-disk partition must be trimmed when writing the split file).
    sig_split=$(jq -r ".[] | select(.type == \"root-${architecture}-verity-sig\") | .split_path" <<<"$output")
    assert_neq "$sig_split" ""
    assert_neq "$sig_split" "null"
    jq . "$sig_split" >/dev/null

    # Check that offline signing works and the resulting image is valid

    output=$(systemd-repart --offline="$OFFLINE" \
                            --definitions="$defs" \
                            --seed="$seed" \
                            --dry-run=no \
                            --empty=create \
                            --size=auto \
                            --json=pretty \
                            --defer-partitions=root-${architecture}-verity-sig \
                            "$imgs/offline")

    offline_drh=$(jq -r ".[] | select(.type == \"root-${architecture}\") | .roothash" <<<"$output")

    echo -n "$offline_drh" | \
        openssl smime -sign -in /dev/stdin \
                      -inkey "$defs/verity.key" \
                      -signer "$defs/verity.crt" \
                      -noattr -binary -outform der \
                      -out "$imgs/offline.roothash.p7s"

    systemd-repart --offline "$OFFLINE" \
                   --definitions "$defs" \
                   --dry-run no \
                   --join-signature "$offline_drh:$imgs/offline.roothash.p7s" \
                   --certificate "$defs/verity.crt" \
                   "$imgs/offline"

    # Check that we can dissect, mount and unmount a repart verity image. (and that the image UUID is deterministic)

    if systemd-detect-virt --quiet --container; then
        echo "Skipping verity test dissect part in container."
        return
    fi

    systemd-dissect "$imgs/verity" --root-hash "$drh"
    systemd-dissect "$imgs/verity" --root-hash "$drh" --json=short | grep '"imageUuid":"1d2ce291-7cce-4f7d-bc83-fdb49ad74ebd"' >/dev/null
    systemd-dissect "$imgs/verity" --root-hash "$drh" -M "$imgs/mnt"
    systemd-dissect -U "$imgs/mnt"

    systemd-dissect "$imgs/offline" --root-hash "$offline_drh"
    systemd-dissect "$imgs/offline" --root-hash "$offline_drh" --json=short | grep '"imageUuid":"1d2ce291-7cce-4f7d-bc83-fdb49ad74ebd"' >/dev/null
    systemd-dissect "$imgs/offline" --root-hash "$offline_drh" -M "$imgs/mnt"
    systemd-dissect -U "$imgs/mnt"
}

testcase_verity_explicit_block_size() {
    local defs imgs loop

    if systemd-detect-virt --quiet --container; then
        echo "Skipping verity block size tests in container."
        return
    fi

    defs="$(mktemp --directory "/tmp/test-repart.defs.XXXXXXXXXX")"
    imgs="$(mktemp --directory "/var/tmp/test-repart.imgs.XXXXXXXXXX")"

    # shellcheck disable=SC2064
    trap "rm -rf '$defs' '$imgs'" RETURN
    chmod 0755 "$defs"

    echo "*** varying-dm-verity-block-sizes ***"

    tee "$defs/verity-data.conf" <<EOF
[Partition]
Type=root-${architecture}
CopyFiles=${defs}
Verity=data
VerityMatchKey=root
Minimize=guess
EOF

    tee "$defs/verity-hash.conf" <<EOF
[Partition]
Type=root-${architecture}-verity
Verity=hash
VerityMatchKey=root
VerityHashBlockSizeBytes=1024
VerityDataBlockSizeBytes=4096
Minimize=yes
EOF

    systemd-repart --offline="$OFFLINE" \
                   --definitions="$defs" \
                   --seed="$seed" \
                   --dry-run=no \
                   --empty=create \
                   --size=auto \
                   --json=pretty \
                   "$imgs/verity"

    loop="$(losetup --partscan --show --find "$imgs/verity")"

    # Make sure the loopback device gets cleaned up
    # shellcheck disable=SC2064
    trap "rm -rf '$defs' '$imgs' ; losetup -d '$loop'" RETURN ERR

    udevadm wait --timeout="$UDEVADM_WAIT_TIMEOUT" --settle "${loop:?}p1" "${loop:?}p2"

    # Check that the verity block sizes are as expected
    veritysetup dump "${loop}p2" | grep 'Data block size:' | grep '4096' >/dev/null
    veritysetup dump "${loop}p2" | grep 'Hash block size:' | grep '1024' >/dev/null
}

testcase_verity_hash_size_from_data_size() {
    local defs imgs loop

    if systemd-detect-virt --quiet --container; then
        echo "Skipping verity hash size from data size test in container."
        return
    fi

    defs="$(mktemp --directory "/tmp/test-repart.defs.XXXXXXXXXX")"
    imgs="$(mktemp --directory "/var/tmp/test-repart.imgs.XXXXXXXXXX")"

    # shellcheck disable=SC2064
    trap "rm -rf '$defs' '$imgs'" RETURN
    chmod 0755 "$defs"

    echo "*** dm-verity-hash-size-from-data-size ***"

    # create minimized data partition with SizeMaxBytes=
    tee "$defs/verity-data.conf" <<EOF
[Partition]
Type=root-${architecture}
CopyFiles=${defs}
Verity=data
VerityMatchKey=root
Minimize=guess
SizeMaxBytes=10G
EOF

    # create hash partition, its size will be derived from SizeMaxBytes= of the data partition
    tee "$defs/verity-hash.conf" <<EOF
[Partition]
Type=root-${architecture}-verity
Verity=hash
VerityMatchKey=root
VerityHashBlockSizeBytes=4096
VerityDataBlockSizeBytes=4096
EOF

    systemd-repart --offline="$OFFLINE" \
                   --definitions="$defs" \
                   --seed="$seed" \
                   --dry-run=no \
                   --empty=create \
                   --size=auto \
                   --json=pretty \
                   "$imgs/verity"

    loop="$(losetup --partscan --show --find "$imgs/verity")"

    # Make sure the loopback device gets cleaned up
    # shellcheck disable=SC2064
    trap "rm -rf '$defs' '$imgs' ; losetup -d '$loop'" RETURN ERR

    udevadm wait --timeout="$UDEVADM_WAIT_TIMEOUT" --settle "${loop:?}p1" "${loop:?}p2"

    output=$(sfdisk -J "$loop")

    # size of the hash partition, as determined by calculate_verity_hash_size()
    # for 10GiB data partition and hash / data block size of 4096B
    hash_bytes=84557824
    hash_sectors_expected=$((hash_bytes / 512))

    hash_sectors_actual=$(jq -r ".partitiontable.partitions | map(select(.name == \"root-${architecture}-verity\")) | .[].size" <<<"$output")

    assert_eq "$hash_sectors_expected" "$hash_sectors_actual"

    data_sectors=$(jq -r ".partitiontable.partitions | map(select(.name == \"root-${architecture}\")) | .[].size" <<<"$output")
    data_bytes=$((data_sectors * 512))
    data_verity_blocks=$((data_bytes / 4096))

    # The actual data partition is much smaller than 10GiB, i.e. also smaller than 100MiB
    assert_rc 0 test $data_bytes -lt $((100 * 1024 * 1024))

    # Check that the verity hash tree is created from the actual on-disk data, not the custom size
    veritysetup dump "${loop}p2" | grep 'Data blocks:' | grep "$data_verity_blocks" >/dev/null
}

testcase_exclude_files() {
    local defs imgs root output

    defs="$(mktemp --directory "/tmp/test-repart.defs.XXXXXXXXXX")"
    imgs="$(mktemp --directory "/var/tmp/test-repart.imgs.XXXXXXXXXX")"
    root="$(mktemp --directory "/var/tmp/test-repart.root.XXXXXXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -rf '$defs' '$imgs' '$root'" RETURN
    chmod 0755 "$defs"

    echo "*** file exclusion ***"

    touch "$root/abc"
    mkdir "$root/usr"
    touch "$root/usr/def"
    touch "$root/usr/qed"
    mkdir "$root/tmp"
    touch "$root/tmp/prs"
    mkdir "$root/proc"
    touch "$root/proc/prs"
    mkdir "$root/zzz"
    mkdir "$root/zzz/usr"
    touch "$root/zzz/usr/prs"
    mkdir "$root/zzz/proc"
    touch "$root/zzz/proc/prs"

    tee "$defs/00-root.conf" <<EOF
[Partition]
Type=root-${architecture}
CopyFiles=/
CopyFiles=/zzz:/
CopyFiles=/:/oiu
ExcludeFilesTarget=/oiu/usr
EOF

    tee "$defs/10-usr.conf" <<EOF
[Partition]
Type=usr-${architecture}
CopyFiles=/usr:/
ExcludeFiles=/usr/qed
EOF

    output=$(systemd-repart --offline="$OFFLINE" \
                            --definitions="$defs" \
                            --seed="$seed" \
                            --dry-run=no \
                            --empty=create \
                            --size=auto \
                            --json=pretty \
                            --root="$root" \
                            "$imgs/zzz")

    if systemd-detect-virt --quiet --container; then
        echo "Skipping issue 24786 test loop/mount parts in container."
        return
    fi

    loop=$(losetup -P --show -f "$imgs/zzz")
    udevadm wait --timeout="$UDEVADM_WAIT_TIMEOUT" --settle "${loop:?}p1" "${loop:?}p2"

    # Test that /usr/def did not end up in the root partition but other files did.
    mkdir "$imgs/mnt"
    mount -t ext4 "${loop}p1" "$imgs/mnt"
    assert_rc 0 ls "$imgs/mnt/abc"
    assert_rc 0 ls "$imgs/mnt/usr"
    assert_rc 2 ls "$imgs/mnt/usr/def"

    # Test that /zzz/usr/prs did not end up in the root partition under /usr but did end up in /zzz/usr/prs
    assert_rc 2 ls "$imgs/mnt/usr/prs"
    assert_rc 0 ls "$imgs/mnt/zzz/usr/prs"

    # Test that /tmp/prs did not end up in the root partition but /tmp did.
    assert_rc 0 ls "$imgs/mnt/tmp"
    assert_rc 2 ls "$imgs/mnt/tmp/prs"

    # Test that /usr/qed did not end up in the usr partition but /usr/def did.
    mount -t ext4 "${loop}p2" "$imgs/mnt/usr"
    assert_rc 0 ls "$imgs/mnt/usr/def"
    assert_rc 2 ls "$imgs/mnt/usr/qed"

    # Test that /zzz/proc/prs did not end up in the root partition but /proc did.
    assert_rc 0 ls "$imgs/mnt/proc"
    assert_rc 2 ls "$imgs/mnt/proc/prs"

    # Test that /zzz/usr/prs did not end up in the usr partition.
    assert_rc 2 ls "$imgs/mnt/usr/prs"

    # Test that /oiu/ and /oiu/zzz ended up in the root partition but /oiu/usr did not.
    assert_rc 0 ls "$imgs/mnt/oiu"
    assert_rc 0 ls "$imgs/mnt/oiu/zzz"
    assert_rc 2 ls "$imgs/mnt/oiu/usr"

    umount -R "$imgs/mnt"
    losetup -d "$loop"
}

testcase_minimize() {
    local defs imgs output

    echo "*** minimization ***"

    defs="$(mktemp --directory "/tmp/test-repart.defs.XXXXXXXXXX")"
    imgs="$(mktemp --directory "/var/tmp/test-repart.imgs.XXXXXXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -rf '$defs' '$imgs'" RETURN

    for format in ext4 vfat erofs; do
        if ! command -v "mkfs.$format" >/dev/null; then
            continue
        fi

        tee "$defs/root-$format.conf" <<EOF
[Partition]
Type=root-${architecture}
Format=${format}
CopyFiles=${defs}
Minimize=guess
EOF
    done

    if command -v mkfs.btrfs >/dev/null; then
        for minimize in guess best; do
            tee "$defs/root-btrfs-${minimize}.conf" <<EOF
[Partition]
Type=root-${architecture}
Format=btrfs
CopyFiles=${defs}
Minimize=${minimize}
EOF
        done
    fi

    if command -v mksquashfs >/dev/null; then
        tee "$defs/root-squashfs.conf" <<EOF
[Partition]
Type=root-${architecture}
Format=squashfs
CopyFiles=${defs}
Minimize=best
EOF
    fi

    output=$(systemd-repart --offline="$OFFLINE" \
                            --definitions="$defs" \
                            --seed="$seed" \
                            --dry-run=no \
                            --empty=create \
                            --size=auto \
                            --json=pretty \
                            "$imgs/zzz")

    # Check that we can dissect, mount and unmount a minimized image.

    if systemd-detect-virt --quiet --container; then
        echo "Skipping minimize dissect, mount and unmount test in container."
        return
    fi

    systemd-dissect "$imgs/zzz"
    systemd-dissect "$imgs/zzz" -M "$imgs/mnt"
    systemd-dissect -U "$imgs/mnt"
}

testcase_free_area_calculation() {
    local defs imgs output

    if ! command -v mksquashfs >/dev/null; then
        echo "Skipping free area calculation test without squashfs."
        return
    fi

    defs="$(mktemp --directory "/tmp/test-repart.defs.XXXXXXXXXX")"
    imgs="$(mktemp --directory "/var/tmp/test-repart.imgs.XXXXXXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -rf '$defs' '$imgs'" RETURN
    chmod 0755 "$defs"

    # https://github.com/systemd/systemd/issues/28225
    echo "*** free area calculation ***"

    tee "$defs/00-ESP.conf" <<EOF
[Partition]
Type         = esp
Label        = ESP
Format       = vfat

SizeMinBytes = 128M
SizeMaxBytes = 128M

# Sufficient for testing
CopyFiles    = /etc:/
EOF

    tee "$defs/10-os.conf" <<EOF
[Partition]
Type           = root-${architecture}
Label          = test
Format         = squashfs

Minimize       = best
# Sufficient for testing
CopyFiles      = /etc/:/

VerityMatchKey = os
Verity         = data
EOF

    tee "$defs/11-os-verity.conf" <<EOF
[Partition]
Type           = root-${architecture}-verity
Label          = test

Minimize       = best

VerityMatchKey = os
Verity         = hash
EOF

    # Set sector size for VFAT to 512 bytes because there will not be enough FAT clusters otherwise
    output1=$(SYSTEMD_REPART_MKFS_OPTIONS_VFAT="-S 512" systemd-repart \
                                              --definitions="$defs" \
                                              --seed="$seed" \
                                              --dry-run=no \
                                              --empty=create \
                                              --size=auto \
                                              --sector-size=4096 \
                                              --defer-partitions=esp \
                                              --json=pretty \
                                              "$imgs/zzz")

    # The second invocation
    output2=$(SYSTEMD_REPART_MKFS_OPTIONS_VFAT="-S 512" systemd-repart \
                                              --definitions="$defs" \
                                              --seed="$seed" \
                                              --dry-run=no \
                                              --empty=allow \
                                              --size=auto \
                                              --sector-size=4096 \
                                              --defer-partitions=esp \
                                              --json=pretty \
                                              "$imgs/zzz")

    diff -u <(echo "$output1" | grep -E "(offset|raw_size|raw_padding)") \
            <(echo "$output2" | grep -E "(offset|raw_size|raw_padding)")
}

test_sector() {
    local defs imgs output loop
    local start size ratio
    local sector="${1?}"

    if systemd-detect-virt --quiet --container; then
        echo "Skipping sector size tests in container."
        return
    fi

    echo "*** sector sizes ***"

    defs="$(mktemp --directory "/tmp/test-repart.defs.XXXXXXXXXX")"
    imgs="$(mktemp --directory "/var/tmp/test-repart.imgs.XXXXXXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -rf '$defs' '$imgs'" RETURN

    tee "$defs/a.conf" <<EOF
[Partition]
Type=root
SizeMaxBytes=15M
SizeMinBytes=15M
EOF
    tee "$defs/b.conf" <<EOF
[Partition]
Type=linux-generic
Weight=250
EOF

    tee "$defs/c.conf" <<EOF
[Partition]
Type=linux-generic
Weight=750
EOF

    truncate -s 100m "$imgs/$sector.img"
    loop=$(losetup -b "$sector" -P --show -f "$imgs/$sector.img" )
    udevadm wait --timeout="$UDEVADM_WAIT_TIMEOUT" --settle "${loop:?}"

    systemd-repart --offline="$OFFLINE" \
                   --pretty=yes \
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

testcase_sector() {
    # Valid block sizes on the Linux block layer are >= 512 and <= PAGE_SIZE, and
    # must be powers of 2. Which leaves exactly four different ones to test on
    # typical hardware
    test_sector 512
    test_sector 1024
    test_sector 2048
    test_sector 4096
}

testcase_dropped_partitions() {
    local workdir image defs

    workdir="$(mktemp --directory "/tmp/test-repart.dropped-partitions.XXXXXXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -rf '${workdir:?}'" RETURN

    image="$workdir/image.img"
    truncate -s 32M "$image"

    defs="$workdir/defs"
    mkdir "$defs"
    echo -ne "[Partition]\nType=root\n" >"$defs/10-part1.conf"
    echo -ne "[Partition]\nType=root\nSizeMinBytes=1T\nPriority=1\n" >"$defs/11-dropped-first.conf"
    echo -ne "[Partition]\nType=root\n" >"$defs/12-part2.conf"
    echo -ne "[Partition]\nType=root\nSizeMinBytes=1T\nPriority=2\n" >"$defs/13-dropped-second.conf"

    systemd-repart --empty=allow --pretty=yes --dry-run=no --definitions="$defs" "$image"

    sfdisk -q -l "$image"
    [[ "$(sfdisk -q -l "$image" | grep -c "$image")" -eq 2 ]]
}

testcase_urandom() {
    local workdir image defs

    workdir="$(mktemp --directory "/tmp/test-repart.urandom.XXXXXXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -rf '${workdir:?}'" RETURN

    image="$workdir/image.img"
    truncate -s 32M "$image"

    defs="$workdir/defs"
    mkdir "$defs"
    echo -ne "[Partition]\nType=swap\nCopyBlocks=/dev/urandom\n" >"$defs/10-urandom.conf"

    systemd-repart --empty=force --pretty=yes --dry-run=no --definitions="$defs" "$image"

    sfdisk -q -l "$image"
    [[ "$(sfdisk -q -l "$image" | grep -c "$image")" -eq 1 ]]
}

testcase_list_devices() {
    systemd-repart --list-devices
}

testcase_compression() {
    local workdir image defs

    workdir="$(mktemp --directory "/tmp/test-repart.compression.XXXXXXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -rf '${workdir:?}'" RETURN

    image="$workdir/image.img"
    defs="$workdir/defs"
    mkdir "$defs"

    # TODO: add btrfs once btrfs-progs v6.11 is available in distributions.
    for format in squashfs erofs; do
        case "$format" in
            squashfs)
                command -v mksquashfs >/dev/null || continue ;;
            *)
                command -v "mkfs.$format" || continue ;;
        esac

        [[ "$format" == "squashfs" ]] && compression=zstd
        [[ "$format" == "erofs" ]] && compression=lz4hc

        tee "$defs/10-root.conf" <<EOF
[Partition]
Type=root
Format=$format
Compression=$compression
CompressionLevel=3
CopyFiles=$defs:/def
SizeMinBytes=48M
EOF

        rm -f "$image"
        systemd-repart --empty=create --size=auto --pretty=yes --dry-run=no --definitions="$defs" "$image"
    done
}

testcase_random_seed() {
    local defs imgs output

    # For issue #34257

    defs="$(mktemp --directory "/tmp/test-repart.defs.XXXXXXXXXX")"
    imgs="$(mktemp --directory "/var/tmp/test-repart.imgs.XXXXXXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -rf '$defs' '$imgs'" RETURN
    chmod 0755 "$defs"

    tee "$defs/root.conf" <<EOF
[Partition]
Type=root
EOF

    tee "$defs/home.conf" <<EOF
[Partition]
Type=home
Label=home-first
EOF

    tee "$defs/swap.conf" <<EOF
[Partition]
Type=swap
SizeMaxBytes=64M
PaddingMinBytes=92M
EOF

    systemd-repart --offline="$OFFLINE" \
                   --definitions="$defs" \
                   --empty=create \
                   --size=1G \
                   --dry-run=no \
                   --seed=random \
                   --offline="$OFFLINE" \
                   --json=pretty \
                   "$imgs/zzz"

    sfdisk -d "$imgs/zzz"
    [[ "$(sfdisk -d "$imgs/zzz" | grep -F 'uuid=' | awk '{ print $8 }' | sort -u | wc -l)" == "3" ]]
}

testcase_make_symlinks() {
    local defs imgs output

    if systemd-detect-virt --quiet --container; then
        echo "Skipping MakeSymlinks= test in container."
        return
    fi

    # For issue #34257

    defs="$(mktemp --directory "/tmp/test-repart.defs.XXXXXXXXXX")"
    imgs="$(mktemp --directory "/var/tmp/test-repart.imgs.XXXXXXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -rf '$defs' '$imgs'" RETURN
    chmod 0755 "$defs"

    tee "$defs/root.conf" <<EOF
[Partition]
Type=root
MakeDirectories=/dir
MakeSymlinks=/foo:/bar
MakeSymlinks=/dir/foo:/bar
MakeSymlinks=/dir/foo-%a:/bar-%a
MakeSymlinks=/dir/bar-%a:../bar-%a
EOF

    systemd-repart --offline="$OFFLINE" \
                   --definitions="$defs" \
                   --empty=create \
                   --size=1G \
                   --dry-run=no \
                   --offline="$OFFLINE" \
                   --json=pretty \
                   "$imgs/zzz"

    systemd-dissect "$imgs/zzz" -M "$imgs/mnt"
    assert_eq "$(readlink "$imgs/mnt/foo")" "/bar"
    assert_eq "$(readlink "$imgs/mnt/dir/foo")" "/bar"
    assert_eq "$(readlink "$imgs/mnt/dir/foo-${architecture}")" "/bar-${architecture}"
    assert_eq "$(readlink "$imgs/mnt/dir/bar-${architecture}")" "../bar-${architecture}"
    systemd-dissect -U "$imgs/mnt"
}

testcase_fallback_partitions() {
    local workdir image defs

    workdir="$(mktemp --directory "/tmp/test-repart.fallback.XXXXXXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -rf '${workdir:?}'" RETURN

    image="$workdir/image.img"
    defs="$workdir/defs"
    mkdir "$defs"

    tee "$defs/10-esp.conf" <<EOF
[Partition]
Type=esp
Format=vfat
SizeMinBytes=10M
EOF

    tee "$defs/20-xbootldr.conf" <<EOF
[Partition]
Type=xbootldr
Format=vfat
SizeMinBytes=100M
SupplementFor=10-esp
EOF

    # Blank disk => big ESP should be created

    systemd-repart --empty=create --size=auto --dry-run=no --definitions="$defs" "$image"

    output=$(sfdisk -d "$image")
    assert_in "${image}1 : start=        2048, size=      532480, type=${esp_guid}" "$output"
    assert_not_in "${image}2" "$output"

    # Disk with small ESP => ESP grows

    sfdisk "$image" <<EOF
label: gpt
size=10M, type=${esp_guid}
EOF

    systemd-repart --dry-run=no --definitions="$defs" "$image"

    output=$(sfdisk -d "$image")
    assert_in "${image}1 : start=        2048, size=      532480, type=${esp_guid}" "$output"
    assert_not_in "${image}2" "$output"

    # Disk with small ESP that can't grow => XBOOTLDR created

    truncate -s 400M "$image"
    sfdisk "$image" <<EOF
label: gpt
size=10M, type=${esp_guid},
size=10M, type=${root_guid},
EOF

    systemd-repart --dry-run=no --definitions="$defs" "$image"

    output=$(sfdisk -d "$image")
    assert_in "${image}1 : start=        2048, size=       20480, type=${esp_guid}" "$output"
    assert_in "${image}3 : start=       43008, size=      776152, type=${xbootldr_guid}" "$output"

    # Disk with existing XBOOTLDR partition => XBOOTLDR grows, small ESP created

    sfdisk "$image" <<EOF
label: gpt
size=10M, type=${xbootldr_guid},
EOF

    systemd-repart --dry-run=no --definitions="$defs" "$image"

    output=$(sfdisk -d "$image")
    assert_in "${image}1 : start=        2048, size=      284632, type=${xbootldr_guid}" "$output"
    assert_in "${image}2 : start=      286680, size=      532480, type=${esp_guid}" "$output"
}

testcase_btrfs() {
    local defs imgs output root

    if ! systemd-analyze compare-versions "$(btrfs --version | head -n 1 | awk '{ print $2 }')" ge v6.12; then
        echo "btrfs-progs is not installed or older than v6.12, skipping test."
        return 0
    fi

    if [[ "$OFFLINE" != "yes" ]]; then
        return 0
    fi

    defs="$(mktemp --directory "/tmp/test-repart.defs.XXXXXXXXXX")"
    imgs="$(mktemp --directory "/var/tmp/test-repart.imgs.XXXXXXXXXX")"
    root="$(mktemp --directory "/var/test-repart.root.XXXXXXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -rf '$defs' '$imgs' '$root'" RETURN
    chmod 0755 "$defs"

    echo "*** testcase for btrfs ***"

    tee "$defs/root.conf" <<EOF
[Partition]
Type=root
Format=btrfs
MakeDirectories=/@ /@home
Subvolumes=/@ /@home
DefaultSubvolume=/@
MountPoint=/:"subvol=@,zstd:1,noatime,lazytime"
MountPoint=/home:"subvol=@home,zstd:1,noatime,lazytime"
EOF

    mkdir -p "$root"/etc

    systemd-repart --pretty=yes \
                   --definitions "$defs" \
                   --empty=create \
                   --size=1G \
                   --seed="$seed" \
                   --dry-run=no \
                   --offline=yes \
                   --generate-fstab "$root"/etc/fstab \
                   "$imgs/btrfs.img"

    sfdisk --dump "$imgs/btrfs.img"

    cat "$root"/etc/fstab
    grep -q 'UUID=[0-9a-f-]* / btrfs discard,rw,nodev,suid,exec,subvol=@,zstd:1,noatime,lazytime 0 1' "$root"/etc/fstab
    grep -q 'UUID=[0-9a-f-]* /home btrfs discard,rw,nodev,suid,exec,subvol=@home,zstd:1,noatime,lazytime 0 1' "$root"/etc/fstab
}

testcase_btrfs_compression() {
    local defs imgs loop output

    if ! systemd-analyze compare-versions "$(btrfs --version | head -n 1 | awk '{ print $2 }')" ge v6.13; then
        echo "btrfs-progs is not installed or older than v6.13, skipping test."
        return 0
    fi

    defs="$(mktemp -d)"
    imgs="$(mktemp -d)"
    # shellcheck disable=SC2064
    trap "rm -rf '$defs' '$imgs'" RETURN
    chmod 0755 "$defs"

    echo "*** testcase for btrfs compression with CopyFiles (OFFLINE=$OFFLINE) ***"

    # Must not be in tmpfs due to exclusions. It also must be large and
    # compressible so that the compression check succeeds later.
    src=/etc/test-source-file
    fallocate -l 1M "$src"

    tee "$defs/btrfs-compressed.conf" <<EOF
[Partition]
Type=linux-generic
Format=btrfs
Compression=zstd
CopyFiles=$src:/test-file
SizeMinBytes=100M
SizeMaxBytes=100M
EOF

    systemd-repart --offline="$OFFLINE" \
                   --definitions="$defs" \
                   --empty=create \
                   --size=auto \
                   --dry-run=no \
                   --seed="$seed" \
                   "$imgs/btrfs-compressed.img" 2>&1 | tee "$imgs/repart-output.txt"
    rm "$src"

    output=$(cat "$imgs/repart-output.txt")

    assert_in "Rootdir from:" "$output"
    assert_in "Compress:" "$output"

    if [[ "$OFFLINE" == "yes" ]] || systemd-detect-virt --quiet --container; then
        echo "Skipping mount verification (requires loop devices)"
        return 0
    fi
    loop="$(losetup -P --show --find "$imgs/btrfs-compressed.img")"
    # shellcheck disable=SC2064
    trap "umount '$imgs/mount' 2>/dev/null || true; losetup -d '$loop' 2>/dev/null || true; rm -rf '$defs' '$imgs'" RETURN
    echo "Loop device: $loop"
    udevadm wait --timeout="$UDEVADM_WAIT_TIMEOUT" --settle "${loop:?}p1"

    mkdir -p "$imgs/mount"
    mount -t btrfs "${loop:?}p1" "$imgs/mount"

    [[ -f "$imgs/mount/test-file" ]]
    [[ "$(stat -c%s "$imgs/mount/test-file")" == "1048576" ]]

    if command -v compsize &>/dev/null; then
        output=$(compsize "$imgs/mount/test-file" 2>&1)
        assert_in "zstd" "$output"
    fi

    umount "$imgs/mount"
    losetup -d "$loop"
}

testcase_varlink_list_devices() {
    REPART="$(which systemd-repart)"
    varlinkctl introspect "$REPART"
    varlinkctl call "$REPART" --graceful=io.systemd.Repart.NoCandidateDevices --collect io.systemd.Repart.ListCandidateDevices '{}'
    varlinkctl call "$REPART" --graceful=io.systemd.Repart.NoCandidateDevices --collect io.systemd.Repart.ListCandidateDevices '{"ignoreRoot":true}'
    varlinkctl call "$REPART" --graceful=io.systemd.Repart.NoCandidateDevices --collect io.systemd.Repart.ListCandidateDevices '{"ignoreEmpty":true}'
    varlinkctl call "$REPART" --graceful=io.systemd.Repart.NoCandidateDevices --collect io.systemd.Repart.ListCandidateDevices '{"ignoreEmpty":true,"ignoreRoot":true}'

    varlinkctl call /run/systemd/io.systemd.Repart --graceful=io.systemd.Repart.NoCandidateDevices --collect io.systemd.Repart.ListCandidateDevices '{"ignoreEmpty":true,"ignoreRoot":true}'
}

testcase_varlink_subscribe_devices() {
    local imgs subscribe_log pre_existing_log loop loop2 mark non_sub_output
    local sub_unit="test-repart-subscribe.service"
    local pre_unit="test-repart-subscribe-pre.service"

    # The uevent monitor in the spawned systemd-repart only sees events from the host's kernel
    # uevent namespace, which an nspawn container with --private-network filters away. Loopback
    # creation also fails inside many container setups.
    if systemd-detect-virt --container >/dev/null 2>&1; then
        echo "Skipping subscribe tests inside container."
        return
    fi

    REPART="$(which systemd-repart)"
    imgs="$(mktemp --directory "/var/tmp/test-repart.subscribe.XXXXXXXXXX")"
    subscribe_log="$(mktemp "/var/tmp/test-repart.subscribe-log.XXXXXXXXXX")"
    pre_existing_log="$(mktemp "/var/tmp/test-repart.pre-log.XXXXXXXXXX")"
    loop=""
    loop2=""

    # Single-quoted trap body so $loop / $loop2 are expanded at trap-fire time, not now.
    # shellcheck disable=SC2016
    trap '
        systemctl stop "$sub_unit" "$pre_unit" 2>/dev/null || true
        [[ -n "${loop:-}"  ]] && systemd-dissect --detach "$loop"  2>/dev/null || true
        [[ -n "${loop2:-}" ]] && systemd-dissect --detach "$loop2" 2>/dev/null || true
        rm -rf "$imgs" "$subscribe_log" "$subscribe_log.err" "$pre_existing_log" "$pre_existing_log.err"
    ' RETURN

    # systemd-dissect --attach requires a dissectable image; a plain ext4 single-filesystem image
    # is the simplest thing it accepts.
    truncate -s 50M "$imgs/loop.img"
    truncate -s 50M "$imgs/loop2.img"
    mkfs.ext4 -F -q -L test-repart-1 "$imgs/loop.img"
    mkfs.ext4 -F -q -L test-repart-2 "$imgs/loop2.img"

    # Make sure no stale unit is sitting around from a previous failed run, then arrange cleanup.
    systemctl reset-failed "$sub_unit" "$pre_unit" 2>/dev/null || true
    systemctl stop "$sub_unit" "$pre_unit" 2>/dev/null || true

    # Start a varlinkctl subscriber as a transient Type=notify service. systemd-run blocks until the
    # service notifies READY=1 -- which varlinkctl does on receipt of the first reply (see
    # src/varlinkctl/varlinkctl.c reply_callback). For us that's either the first "add" of the
    # initial enumeration or the "ready" sentinel; either way we are guaranteed the server-side
    # monitor is up before we trigger any uevents.
    start_subscriber() {
        local unit="$1" log="$2" params="$3"

        systemd-run \
            --quiet \
            --unit="$unit" \
            --collect \
            --service-type=notify \
            --property=StandardOutput="truncate:$log" \
            --property=StandardError="truncate:$log.err" \
            -- \
            varlinkctl --more --timeout=infinity --json=short call \
            "$REPART" io.systemd.Repart.ListCandidateDevices "$params"
    }

    # Poll for a regex match in $1 of the named log file ($3, default $subscribe_log), starting from
    # byte offset $2. Prints the new byte offset (post-match) on stdout so the caller can advance.
    expect_event() {
        local pat="$1" mark_="$2" file="${3:-$subscribe_log}"
        local deadline_=$((SECONDS + UDEVADM_WAIT_TIMEOUT))
        local cur

        while (( SECONDS < deadline_ )); do
            cur=$(stat -c%s "$file" 2>/dev/null || echo 0)
            if (( cur > mark_ )) && \
               tail -c +"$((mark_ + 1))" "$file" | grep -a -E "$pat" >/dev/null; then
                printf '%s\n' "$cur"
                return 0
            fi
            sleep 0.1
        done

        echo "FAIL: pattern '$pat' did not appear within ${UDEVADM_WAIT_TIMEOUT}s. Output past offset $mark_:" >&2
        tail -c +"$((mark_ + 1))" "$file" >&2 || true
        return 1
    }

    # === Test 1: subscribing produces a "ready" sentinel even on an empty initial set ===
    start_subscriber "$sub_unit" "$subscribe_log" \
        '{"ignoreRoot":true,"ignoreEmpty":true,"subscribe":true}'
    mark=$(expect_event '"action":"ready"' 0) || return 1

    # === Test 2: a freshly-added loopback produces an "add" event ===
    loop="$(systemd-dissect --attach --loop-ref=test-repart-1 "$imgs/loop.img")"
    udevadm wait --timeout="$UDEVADM_WAIT_TIMEOUT" --settle "$loop"
    mark=$(expect_event "\"action\":\"add\".*\"node\":\"$loop\"" "$mark") || return 1

    # === Test 3: detaching the loopback produces a "remove" event ===
    systemd-dissect --detach "$loop"
    udevadm wait --timeout="$UDEVADM_WAIT_TIMEOUT" --removed --settle "$loop"
    mark=$(expect_event "\"action\":\"remove\".*\"node\":\"$loop\"" "$mark") || return 1
    loop=""

    # === Test 4: five add/remove cycles in a row stay in sync ===
    for _ in 1 2 3 4 5; do
        loop="$(systemd-dissect --attach --loop-ref=test-repart-1 "$imgs/loop.img")"
        udevadm wait --timeout="$UDEVADM_WAIT_TIMEOUT" --settle "$loop"
        mark=$(expect_event "\"action\":\"add\".*\"node\":\"$loop\"" "$mark") || return 1

        systemd-dissect --detach "$loop"
        udevadm wait --timeout="$UDEVADM_WAIT_TIMEOUT" --removed --settle "$loop"
        mark=$(expect_event "\"action\":\"remove\".*\"node\":\"$loop\"" "$mark") || return 1
        loop=""
    done

    # === Test 5: two coexisting loop devices each produce their own events ===
    # Set them up (and tear them down) one at a time and wait for each device in turn, so events
    # appear in a strict order and we can advance our mark monotonically.
    loop="$(systemd-dissect --attach --loop-ref=test-repart-1 "$imgs/loop.img")"
    udevadm wait --timeout="$UDEVADM_WAIT_TIMEOUT" --settle "$loop"
    mark=$(expect_event "\"action\":\"add\".*\"node\":\"$loop\"" "$mark") || return 1

    loop2="$(systemd-dissect --attach --loop-ref=test-repart-2 "$imgs/loop2.img")"
    udevadm wait --timeout="$UDEVADM_WAIT_TIMEOUT" --settle "$loop2"
    mark=$(expect_event "\"action\":\"add\".*\"node\":\"$loop2\"" "$mark") || return 1

    systemd-dissect --detach "$loop2"
    udevadm wait --timeout="$UDEVADM_WAIT_TIMEOUT" --removed --settle "$loop2"
    mark=$(expect_event "\"action\":\"remove\".*\"node\":\"$loop2\"" "$mark") || return 1
    loop2=""

    systemd-dissect --detach "$loop"
    udevadm wait --timeout="$UDEVADM_WAIT_TIMEOUT" --removed --settle "$loop"
    mark=$(expect_event "\"action\":\"remove\".*\"node\":\"$loop\"" "$mark") || return 1
    loop=""

    # Tear down the first subscriber before starting the next one.
    systemctl stop "$sub_unit"

    # === Test 6: a device that exists *before* subscribe starts shows up in the initial enumeration,
    # and "ready" arrives only after it ===
    loop="$(systemd-dissect --attach --loop-ref=test-repart-1 "$imgs/loop.img")"
    udevadm wait --timeout="$UDEVADM_WAIT_TIMEOUT" --settle "$loop"

    start_subscriber "$pre_unit" "$pre_existing_log" \
        '{"ignoreRoot":true,"subscribe":true}'

    # systemd-run returned (Type=notify => first reply already received), but "ready" may not be
    # written yet -- poll for it.
    expect_event '"action":"ready"' 0 "$pre_existing_log" >/dev/null || return 1

    # Everything up to (but excluding) "ready" is the initial enumeration; it must contain $loop.
    if ! sed -n '/"action":"ready"/q;p' "$pre_existing_log" | \
            grep -a -E "\"action\":\"add\".*\"node\":\"$loop\"" >/dev/null; then
        echo "FAIL: pre-existing loop device $loop not in initial enumeration:" >&2
        cat "$pre_existing_log" >&2
        return 1
    fi

    systemctl stop "$pre_unit"

    # === Test 7: without subscribe the reply has no "action" field (back-compat for older clients) ===
    non_sub_output="$(varlinkctl --collect --json=short call \
        "$REPART" --graceful=io.systemd.Repart.NoCandidateDevices \
        io.systemd.Repart.ListCandidateDevices '{"ignoreRoot":true}')"
    assert_not_in '"action"' "$non_sub_output"
    # Sanity-check: our $loop *is* in that output (so the assertion above wasn't vacuous).
    assert_in "\"node\":\"$loop\"" "$non_sub_output"

    systemd-dissect --detach "$loop"
    loop=""
}

testcase_get_size() {
    local defs

    defs="$(mktemp --directory "/tmp/test-repart.defs.XXXXXXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -rf '$defs'" RETURN

    tee "$defs/a.conf" <<EOF
[Partition]
Type=root
SizeMinBytes=15M
EOF
    tee "$defs/b.conf" <<EOF
[Partition]
Type=linux-generic
SizeMinBytes=23M
EOF

    output="$(systemd-repart --definitions="$defs" - 2>&1)"
    assert_in "Automatically determined minimal disk image size as 39M." "$output"
}

testcase_varlink_run() {
    local defs

    defs="$(mktemp --directory "/tmp/test-repart.defs.XXXXXXXXXX")"
    imgs="$(mktemp --directory "/var/tmp/test-repart.imgs.XXXXXXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -rf '$defs' '$imgs'" RETURN

    tee "$defs/a.conf" <<EOF
[Partition]
Type=root
Format=empty
EOF
    tee "$defs/b.conf" <<EOF
[Partition]
Type=linux-generic
Format=empty
EOF

    systemd-repart --pretty=yes \
                   --definitions "$defs" \
                   --empty=create \
                   --size=50M \
                   --seed="$seed" \
                   --dry-run=no \
                   --offline=yes \
                   "$imgs/disk1.img"

    REPART="$(which systemd-repart)"
    truncate -s 50M "$imgs/disk2.img"
    varlinkctl call "$REPART" io.systemd.Repart.Run '{"definitions":["'"$defs"'"],"empty":"force","seed":"'"$seed"'","dryRun":false,"node":"'"$imgs/disk2.img"'"}'

    # Compare that the version from the command line and via Varlink result in the bit exact same output
    cmp "$imgs/disk1.img" "$imgs/disk2.img"

    # Try once more, this time with progress info
    truncate -s 50M "$imgs/disk3.img"
    varlinkctl --more --collect call "$REPART" io.systemd.Repart.Run '{"definitions":["'"$defs"'"],"empty":"force","seed":"'"$seed"'","dryRun":false,"node":"'"$imgs/disk3.img"'"}'

    cmp "$imgs/disk1.img" "$imgs/disk3.img"
}

_test_luks2_integrity() {
    local defs imgs output root

    if [[ "$OFFLINE" != "no" ]]; then
        return 0
    fi

    defs="$(mktemp --directory "/tmp/test-repart.defs.XXXXXXXXXX")"
    imgs="$(mktemp --directory "/var/tmp/test-repart.imgs.XXXXXXXXXX")"
    root="$(mktemp --directory "/var/test-repart.root.XXXXXXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -rf '$defs' '$imgs' '$root'" RETURN
    chmod 0755 "$defs"

    echo "*** testcase for LUKS2 integrity ***"

    tee "$defs/root.conf" <<EOF
[Partition]
Type=root
Format=ext4
Encrypt=key-file
Integrity=inline
EOF

    [ -n "$1" ] && echo "IntegrityAlgorithm=$1" >> "$defs/root.conf"

    systemd-repart --pretty=yes \
                   --definitions "$defs" \
                   --empty=create \
                   --size=100M \
                   --seed="$seed" \
                   --dry-run=no \
                   --offline=no \
                   "$imgs/encint.img"

    loop="$(losetup -P --show --find "$imgs/encint.img")"
    udevadm wait --timeout="$UDEVADM_WAIT_TIMEOUT" --settle "${loop:?}p1"

    volume="test-repart-luksint-$RANDOM"
    dmstatus="$imgs/dmsetup-$RANDOM"

    touch "$imgs/empty-password"

    # the expectation for hmac-sha256 is 'integrity: hmac(sha256)'
    cryptsetup luksDump "${loop}p1" | grep "integrity: $(echo "$1" | sed -r 's/^hmac-(.*)$/hmac(\1)/')" >/dev/null

    cryptsetup open --type=luks2 --key-file="$imgs/empty-password" "${loop}p1" "$volume"
    dmsetup status > "$dmstatus"
    cryptsetup close "$volume"
    losetup -d "$loop"
    # Check that there's a dm-integrity entry
    grep -q "$volume""_dif.* integrity " "$dmstatus"
}

testcase_luks2_integrity() {
    _test_luks2_integrity ""
    _test_luks2_integrity "hmac-sha1"
    _test_luks2_integrity "hmac-sha256"
    _test_luks2_integrity "hmac-sha512"
}

testcase_ext_reproducibility() {
    local defs imgs ts

    # Online mode mounts the filesystem which updates inode timestamps non-deterministically
    if [[ "$OFFLINE" != "yes" ]]; then
        echo "Skipping ext reproducibility test in online mode."
        return 0
    fi

    defs="$(mktemp --directory "/tmp/test-repart.defs.XXXXXXXXXX")"
    imgs="$(mktemp --directory "/var/tmp/test-repart.imgs.XXXXXXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -rf '$defs' '$imgs'" RETURN

    tee "$defs/root.conf" <<EOF
[Partition]
Type=root
Format=ext4
EOF

    # Build the image twice with the same seed and verify they are identical
    ts=$(date +%s)
    env SOURCE_DATE_EPOCH="$ts" \
        systemd-repart \
        --offline="$OFFLINE" \
        --definitions="$defs" \
        --empty=create \
        --size=50M \
        --seed="$seed" \
        --dry-run=no \
        "$imgs/test1.img"

    sleep 2

    env SOURCE_DATE_EPOCH="$ts" \
        systemd-repart \
        --offline="$OFFLINE" \
        --definitions="$defs" \
        --empty=create \
        --size=50M \
        --seed="$seed" \
        --dry-run=no \
        "$imgs/test2.img"

    cmp "$imgs/test1.img" "$imgs/test2.img"
}

testcase_luks2_keyhash() {
    local defs imgs output root

    defs="$(mktemp --directory "/tmp/test-repart.defs.XXXXXXXXXX")"
    imgs="$(mktemp --directory "/var/tmp/test-repart.imgs.XXXXXXXXXX")"
    root="$(mktemp --directory "/var/test-repart.root.XXXXXXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -rf '$defs' '$imgs' '$root'" RETURN
    chmod 0755 "$defs"

    echo "*** testcase for fixate-volume-key ***"

    volume="test-repart-lukskeyhash-$RANDOM"

    tee "$defs/root.conf" <<EOF
[Partition]
Type=linux-generic
Format=ext4
Encrypt=key-file
EncryptedVolume=$volume:::fixate-volume-key
EOF

    systemd-repart --pretty=yes \
                   --definitions "$defs" \
                   --empty=create \
                   --size=100M \
                   --seed="$seed" \
                   --dry-run=no \
                   --offline="$OFFLINE" \
                   --generate-crypttab="$imgs/crypttab" \
                   "$imgs/enckeyhash.img"

    loop="$(losetup -P --show --find "$imgs/enckeyhash.img")"
    udevadm wait --timeout="$UDEVADM_WAIT_TIMEOUT" --settle "${loop:?}p1"

    touch "$imgs/empty-password"

    # Check that the volume can be attached with the correct hash
    expected_hash="$(grep UUID= "$imgs/crypttab" | sed s,.*fixate-volume-key=,,)"
    echo "Expected hash: $expected_hash"
    echo "Trying to attach the volume"
    systemd-cryptsetup attach $volume "${loop}p1" "$imgs/empty-password" "fixate-volume-key=$expected_hash"
    echo "Trying to detach the volume"
    systemd-cryptsetup detach $volume
    echo "Success!"

    # Check that the volume cannot be attached with incorrect hash
    echo "Trying to attach the volume with wrong hash"
    systemd-cryptsetup attach $volume "${loop}p1" "$imgs/empty-password" "fixate-volume-key=aaaaaabbbbbbccccccddddddeeeeeeffffff1111112222223333334444445555" && exit 1
    # Verify the volume is not attached
    [ ! -f "/dev/mapper/$volume" ] || exit 1

    losetup -d "$loop"
}

testcase_fstab_crypttab_in_repart() {
    local defs imgs root volume

    defs="$(mktemp --directory "/tmp/test-repart.defs.XXXXXXXXXX")"
    imgs="$(mktemp --directory "/var/tmp/test-repart.imgs.XXXXXXXXXX")"
    root="$(mktemp --directory "/var/test-repart.root.XXXXXXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -rf '$defs' '$imgs' '$root'" RETURN
    chmod 0755 "$defs"

    echo "*** testcase for including fstab/crypttab into repart created volume ***"

    volume="test-repart-fstab-crypttab-$RANDOM"

    mkdir -p "$root/etc"
    tee "$defs/root.conf" <<EOF
[Partition]
Type=linux-generic
Format=ext4
CopyFiles=/etc
Encrypt=key-file
EncryptedVolume=$volume
MountPoint=/mnt/volume
EOF

    systemd-repart --pretty=yes \
                   --definitions "$defs" \
                   --empty=create \
                   --size=100M \
                   --seed="$seed" \
                   --dry-run=no \
                   --offline="$OFFLINE" \
                   --generate-fstab="/etc/fstab" \
                   --generate-crypttab="/etc/crypttab" \
                   --root="$root" \
                   "$imgs/fstabcrypttabrepart.img"

    loop="$(losetup -P --show --find "$imgs/fstabcrypttabrepart.img")"
    udevadm wait --timeout="$UDEVADM_WAIT_TIMEOUT" --settle "${loop:?}p1"

    touch "$imgs/empty-password"

    mkdir -p "$imgs/mount"

    systemd-cryptsetup attach "$volume" "${loop}p1" "$imgs/empty-password"

    mount -t ext4 "/dev/mapper/$volume" "$imgs/mount"

    echo "Testing /etc/fstab presence"
    test -f "$imgs/mount/etc/fstab"
    grep -q "/mnt/volume" "$imgs/mount/etc/fstab"

    echo "Testing /etc/crypttab presence"
    test -f "$imgs/mount/etc/crypttab"
    grep -q "$volume" "$imgs/mount/etc/crypttab"

    umount "$imgs/mount"
    systemd-cryptsetup detach "$volume"

    losetup -d "$loop"
}

testcase_encrypted_volume_empty_name() {
    local defs imgs

    defs="$(mktemp --directory "/tmp/test-repart.defs.XXXXXXXXXX")"
    imgs="$(mktemp --directory "/var/tmp/test-repart.imgs.XXXXXXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -rf '$defs' '$imgs'" RETURN
    chmod 0755 "$defs"

    echo "*** testcase for EncryptedVolume= with empty volume name ***"

    tee "$defs/root.conf" <<EOF
[Partition]
Type=linux-generic
Format=ext4
Encrypt=key-file
EncryptedVolume=:none:discard
EOF

    systemd-repart --pretty=yes \
                   --definitions "$defs" \
                   --empty=create \
                   --size=100M \
                   --seed="$seed" \
                   --dry-run=no \
                   --offline="$OFFLINE" \
                   --generate-crypttab="$imgs/crypttab" \
                   "$imgs/emptyvolname.img"

    # systemd-repart should fill in volume name as luks-UUID
    grep -Eq '^luks-[0-9a-f-]{36} UUID=[0-9a-f-]{36} none discard$' \
        "$imgs/crypttab"
}

testcase_block_device_replace() {
    if [[ "$OFFLINE" == "yes" ]]; then
        return 0
    fi

    if ! command -v btrfs >/dev/null; then
        echo "btrfs not found, skipping."
        return 0
    fi

    if ! command -v mkfs.btrfs >/dev/null; then
        echo "mkfs.btrfs not found, skipping."
        return 0
    fi

    local defs imgs btrfs_mntpoint_plain btrfs_mntpoint_encrypted
    local loop loop_btrfs_plain loop_btrfs_encrypted
    local dm_btrfs_encrypted encrypted_device

    btrfs_mntpoint_plain="$(mktemp --directory "/tmp/test-repart.btrfs-mntpoint-plain.XXXXXXXXXX")"
    btrfs_mntpoint_encrypted="$(mktemp --directory "/tmp/test-repart.btrfs-mntpoint-encrypted.XXXXXXXXXX")"
    defs="$(mktemp --directory "/tmp/test-repart.defs.XXXXXXXXXX")"
    imgs="$(mktemp --directory "/var/tmp/test-repart.imgs.XXXXXXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -rf '$defs' '$imgs' '$btrfs_mntpoint_plain' '$btrfs_mntpoint_encrypted'" RETURN
    chmod 0755 "$defs"

    truncate --size 500M "${imgs}/btrfs-plain"
    mkfs.btrfs "${imgs}/btrfs-plain"
    loop_btrfs_plain="$(losetup --show --find "$imgs/btrfs-plain")"
    # shellcheck disable=SC2064
    trap "losetup -d '${loop_btrfs_plain}'; rm -rf '$defs' '$imgs' '$btrfs_mntpoint_plain' '$btrfs_mntpoint_encrypted'" RETURN

    mount "${loop_btrfs_plain}" "${btrfs_mntpoint_plain}"
    echo tada >"${btrfs_mntpoint_plain}/magic-plain"

    # shellcheck disable=SC2064
    trap "umount '${btrfs_mntpoint_plain}'; losetup -d '${loop_btrfs_plain}'; rm -rf '$defs' '$imgs' '$btrfs_mntpoint_plain' '$btrfs_mntpoint_encrypted'" RETURN

    truncate --size 500M "${imgs}/btrfs-encrypted"
    mkfs.btrfs "${imgs}/btrfs-encrypted"
    loop_btrfs_encrypted="$(losetup --show --find "$imgs/btrfs-encrypted")"
    # shellcheck disable=SC2064
    trap "losetup -d '${loop_btrfs_encrypted}'; umount '${btrfs_mntpoint_plain}'; losetup -d '${loop_btrfs_plain}'; rm -rf '$defs' '$imgs' '$btrfs_mntpoint_plain' '$btrfs_mntpoint_encrypted'" RETURN

    mount "${loop_btrfs_encrypted}" "${btrfs_mntpoint_encrypted}"
    echo tada >"${btrfs_mntpoint_encrypted}/magic-encrypted"

    # shellcheck disable=SC2064
    trap "umount '${btrfs_mntpoint_encrypted}'; losetup -d '${loop_btrfs_encrypted}'; umount '${btrfs_mntpoint_plain}'; losetup -d '${loop_btrfs_plain}'; rm -rf '$defs' '$imgs' '$btrfs_mntpoint_plain' '$btrfs_mntpoint_encrypted'" RETURN

    truncate --size 2G "${imgs}/img"

    tee "$defs/01-plain.conf" <<EOF
[Partition]
Type=linux-generic
Label=plain
BlockDeviceReplace=${btrfs_mntpoint_plain}
EOF

    tee "$defs/02-encrypted.conf" <<EOF
[Partition]
Type=linux-generic
Label=encrypted
Encrypt=key-file
BlockDeviceReplace=${btrfs_mntpoint_encrypted}
VolumeName=btrfs-replace-encrypted
EOF

    loop="$(losetup -P --show --find "${imgs}/img")"
    # shellcheck disable=SC2064
    trap "umount '${btrfs_mntpoint_encrypted}'; cryptsetup close btrfs-replace-encrypted || true; losetup -d '${loop_btrfs_encrypted}'; umount '${btrfs_mntpoint_plain}'; losetup -d '${loop_btrfs_plain}'; losetup -d '${loop}'; rm -rf '$defs' '$imgs' '$btrfs_mntpoint_plain' '$btrfs_mntpoint_encrypted'" RETURN

    touch "${imgs}/empty-password"

    systemd-repart --offline="$OFFLINE" \
                   --definitions="$defs" \
                   --empty=require \
                   --key-file="${imgs}/empty-password" \
                   --seed="$seed" \
                   --dry-run=no \
                   "${loop}"

    assert_eq "$(findmnt "${btrfs_mntpoint_plain}" -o SOURCE -n)" "${loop}p1"
    dm_btrfs_encrypted="$(findmnt "${btrfs_mntpoint_encrypted}" -o SOURCE -n)"
    if [[ "$dm_btrfs_encrypted" != "/dev/mapper/btrfs-replace-encrypted" ]]; then
        # When libdevmapper is built without UDEV_SYNC_SUPPORT (e.g. on Alpine/postmarketOS),
        # it creates a device node under /dev/mapper/ instead of relying on udev to create a symlink.
        # In this case, verify that both device nodes refer to the same underlying device.
        assert_eq "$(stat -c %Hr:%Lr "$dm_btrfs_encrypted")" "$(stat -c %Hr:%Lr /dev/mapper/btrfs-replace-encrypted)"
    fi
    encrypted_device="/sys/dev/block/$(dmsetup table /dev/mapper/btrfs-replace-encrypted | cut -d" " -f7)"
    assert_eq "$(udevadm info --query=property --property=DEVNAME --value "${encrypted_device}")" "${loop}p2"
    grep -q tada "${btrfs_mntpoint_plain}/magic-plain"
    grep -q tada "${btrfs_mntpoint_encrypted}/magic-encrypted"
}

testcase_insert_into_gap() {
    local defs imgs output

    defs="$(mktemp --directory "/tmp/test-repart.defs.XXXXXXXXXX")"
    imgs="$(mktemp --directory "/var/tmp/test-repart.imgs.XXXXXXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -rf '$defs' '$imgs'" RETURN
    chmod 0755 "$defs"

    echo "*** Inserting a new partition into a gap between two existing partitions ***"

    truncate -s 71M "$imgs/gap.img"
    sfdisk "$imgs/gap.img" <<EOF
label: gpt
size=10M, type=${esp_guid}, name="part-a",
start=60M, size=10M, type=${root_guid}, name="part-c",
EOF

    tee "$defs/new.conf" <<EOF
[Partition]
Type=usr
Label=part-b
SizeMinBytes=10M
SizeMaxBytes=10M
EOF

    systemd-repart --offline="$OFFLINE" \
                   --definitions="$defs" \
                   --seed="$seed" \
                   --dry-run=no \
                   "$imgs/gap.img"

    output=$(sfdisk --dump "$imgs/gap.img")

    assert_in "$imgs/gap.img1 : start=        2048, size=       20480," "$output"
    assert_in "$imgs/gap.img2 : start=      122880, size=       20480," "$output"

    # New partition B must start at the beginning of the gap (after A), not at
    # the end (before C).
    assert_in "$imgs/gap.img3 : start=       22528, size=       20480, type=$usr_guid, uuid=$usr_uuid, name=\"part-b\"" "$output"
}

OFFLINE="yes"
run_testcases

# Online image builds need loop devices so we can't run them in nspawn.
if ! systemd-detect-virt --container; then
    OFFLINE="no"
    run_testcases
fi

touch /testok
