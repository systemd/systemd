#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

if ! command -v systemd-repart &>/dev/null; then
    echo "no systemd-repart" >/skipped
    exit 0
fi

export SYSTEMD_LOG_LEVEL=debug
export PAGER=cat

machine="$(uname -m)"
if [ "${machine}" = "x86_64" ]; then
    root_guid=4f68bce3-e8cd-4db1-96e7-fbcaf984b709
    root_uuid=60F33797-1D71-4DCB-AA6F-20564F036CD0
    usr_guid=8484680c-9521-48c6-9c11-b0720656f69e
    usr_uuid=7E3369DD-D653-4513-ADF5-B993A9F20C16
    architecture="x86-64"
elif [ "${machine}" = "i386" ] || [ "${machine}" = "i686" ] || [ "${machine}" = "x86" ]; then
    root_guid=44479540-f297-41b2-9af7-d131d5f0458a
    root_uuid=02b4253f-29a4-404e-8972-1669d3b03c87
    usr_guid=75250d76-8cc6-458e-bd66-bd47cc81a812
    usr_uuid=7b42ffb0-b0e1-4395-b20b-c78f4a571648
    architecture="x86"
elif [ "${machine}" = "aarch64" ] || [ "${machine}" = "aarch64_be" ] || [ "${machine}" = "armv8b" ] || [ "${machine}" = "armv8l" ]; then
    root_guid=b921b045-1df0-41c3-af44-4c6f280d3fae
    root_uuid=055d0227-53a6-4033-85c3-9a5973eff483
    usr_guid=b0e01050-ee5f-4390-949a-9101b17104e9
    usr_uuid=fce3c75e-d6a4-44c0-87f0-4c105183fb1f
    architecture="arm64"
elif [ "${machine}" = "arm" ]; then
    root_guid=69dad710-2ce4-4e3c-b16c-21a1d49abed3
    root_uuid=567da89e-8de2-4499-8d10-18f212dff034
    usr_guid=7d0359a3-02b3-4f0a-865c-654403e70625
    usr_uuid=71e93dc2-5073-42cb-8a84-a354e64d8966
    architecture="arm"
elif [ "${machine}" = "loongarch64" ]; then
    root_guid=77055800-792c-4f94-b39a-98c91b762bb6
    root_uuid=d8efc2d2-0133-41e4-bdcb-3b9f4cfddde8
    usr_guid=e611c702-575c-4cbe-9a46-434fa0bf7e3f
    usr_uuid=031ffa75-00bb-49b6-a70d-911d2d82a5b7
    architecture="loongarch64"
elif [ "${machine}" = "ia64" ]; then
    root_guid=993d8d3d-f80e-4225-855a-9daf8ed7ea97
    root_uuid=dcf33449-0896-4ea9-bc24-7d58aeef522d
    usr_guid=4301d2a6-4e3b-4b2a-bb94-9e0b2c4225ea
    usr_uuid=bc2bcce7-80d6-449a-85cc-637424ce5241
    architecture="ia64"
elif [ "${machine}" = "s390x" ]; then
    root_guid=5eead9a9-fe09-4a1e-a1d7-520d00531306
    root_uuid=7ebe0c85-e27e-48ec-b164-f4807606232e
    usr_guid=8a4f5770-50aa-4ed3-874a-99b710db6fea
    usr_uuid=51171d30-35cf-4a49-b8b5-9478b9b796a5
    architecture="s390x"
elif [ "${machine}" = "ppc64le" ]; then
    root_guid=c31c45e6-3f39-412e-80fb-4809c4980599
    root_uuid=061e67a1-092f-482f-8150-b525d50d6654
    usr_guid=15bb03af-77e7-4d4a-b12b-c0d084f7491c
    usr_uuid=c0d0823b-8040-4c7c-a629-026248e297fb
    architecture="ppc64-le"
else
    echo "Unexpected uname -m: ${machine} in testsuite-58.sh, please fix me"
    exit 1
fi

rm -f /var/tmp/testsuite-58.img /var/tmp/testsuite-58.2.img /tmp/testsuite-58.dump
mkdir -p /tmp/testsuite-58-defs/

# First part: create a disk image and verify its in order

cat >/tmp/testsuite-58-defs/esp.conf <<EOF
[Partition]
Type=esp
SizeMinBytes=10M
Format=vfat
EOF

cat >/tmp/testsuite-58-defs/usr.conf <<EOF
[Partition]
Type=usr-${architecture}
SizeMinBytes=10M
Format=ext4
ReadOnly=yes
EOF

cat >/tmp/testsuite-58-defs/root.conf <<EOF
[Partition]
Type=root-${architecture}
SizeMinBytes=10M
Format=ext4
MakeDirectories=/usr /efi
EOF

systemd-repart --definitions=/tmp/testsuite-58-defs/ \
               --empty=create \
               --size=auto \
               --seed=750b6cd5c4ae4012a15e7be3c29e6a47 \
               /var/tmp/testsuite-58.img

sfdisk --dump /var/tmp/testsuite-58.img | tee /tmp/testsuite-58.dump

grep -qixF "/var/tmp/testsuite-58.img1 : start=        2048, size=       20480, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, uuid=39107B09-615D-48FB-BA37-C663885FCE67, name=\"esp\"" /tmp/testsuite-58.dump
grep -qixF "/var/tmp/testsuite-58.img2 : start=       22528, size=       20480, type=${root_guid}, uuid=${root_uuid}, name=\"root-${architecture}\", attrs=\"GUID:59\"" /tmp/testsuite-58.dump
grep -qixF "/var/tmp/testsuite-58.img3 : start=       43008, size=       20480, type=${usr_guid}, uuid=${usr_uuid}, name=\"usr-${architecture}\", attrs=\"GUID:60\"" /tmp/testsuite-58.dump

# Second part, duplicate it with CopyBlocks=auto

cat >/tmp/testsuite-58-defs/esp.conf <<EOF
[Partition]
Type=esp
CopyBlocks=auto
EOF

cat >/tmp/testsuite-58-defs/usr.conf <<EOF
[Partition]
Type=usr-${architecture}
ReadOnly=yes
CopyBlocks=auto
EOF

cat >/tmp/testsuite-58-defs/root.conf <<EOF
[Partition]
Type=root-${architecture}
CopyBlocks=auto
EOF

systemd-repart --definitions=/tmp/testsuite-58-defs/ \
               --empty=create \
               --size=auto \
               --seed=750b6cd5c4ae4012a15e7be3c29e6a47 \
               --image=/var/tmp/testsuite-58.img \
               /var/tmp/testsuite-58.2.img

cmp /var/tmp/testsuite-58.img /var/tmp/testsuite-58.2.img

rm /var/tmp/testsuite-58.img /var/tmp/testsuite-58.2.img /tmp/testsuite-58.dump
rm -r /tmp/testsuite-58-defs/

# Third part: operate on an an image with unaligned partition, to see if that works.

rm -f /var/tmp/testsuite-58.3.img /tmp/testsuite-58-3.dump
mkdir -p /tmp/testsuite-58.3-defs/

cat >/tmp/testsuite-58.3-defs/root.conf <<EOF
[Partition]
Type=root-${architecture}
EOF

truncate -s 10g /var/tmp/testsuite-58.3.img
sfdisk /var/tmp/testsuite-58.3.img <<EOF
label: gpt

start=2048, size=69044
start=71092, size=3591848
EOF

systemd-repart --definitions=/tmp/testsuite-58.3-defs/ \
               --seed=750b6cd5c4ae4012a15e7be3c29e6a47 \
               --dry-run=no \
               /var/tmp/testsuite-58.3.img

sfdisk --dump /var/tmp/testsuite-58.3.img | tee /tmp/testsuite-58.3.dump

grep -qF '/var/tmp/testsuite-58.3.img1 : start=        2048, size=       69044,' /tmp/testsuite-58.3.dump
grep -qF '/var/tmp/testsuite-58.3.img2 : start=       71092, size=     3591848,' /tmp/testsuite-58.3.dump
grep -qixF "/var/tmp/testsuite-58.3.img3 : start=     3662944, size=    17308536, type=${root_guid}, uuid=${root_uuid}, name=\"root-${architecture}\", attrs=\"GUID:59\"" /tmp/testsuite-58.3.dump

rm /var/tmp/testsuite-58.3.img /tmp/testsuite-58.3.dump
rm -r /tmp/testsuite-58.3-defs/

# testcase for #21817
mkdir -p /tmp/testsuite-58-issue-21817-defs/
truncate -s 100m /tmp/testsuite-58-issue-21817.img
LOOP=$(losetup -P --show -f /tmp/testsuite-58-issue-21817.img)
printf 'size=50M,type=%s\n,\n' "${root_guid}" | sfdisk -X gpt /tmp/testsuite-58-issue-21817.img
cat >/tmp/testsuite-58-issue-21817-defs/test.conf <<EOF
[Partition]
Type=root
EOF
systemd-repart --pretty=yes --definitions /tmp/testsuite-58-issue-21817-defs/ "$LOOP"
sfdisk --dump "$LOOP" | tee /tmp/testsuite-58-issue-21817.dump
losetup -d "$LOOP"

grep -qiF "p1 : start=        2048, size=      102400, type=${root_guid}," /tmp/testsuite-58-issue-21817.dump
# Accept both unpadded (pre-v2.38 util-linux) and padded (v2.38+ util-linux) sizes
grep -qE "p2 : start=      104448, size=      (100319| 98304)," /tmp/testsuite-58-issue-21817.dump

rm /tmp/testsuite-58-issue-21817.img /tmp/testsuite-58-issue-21817.dump
rm -r /tmp/testsuite-58-issue-21817-defs/

testsector()
{
    echo "Running sector test with sector size $1..."

    mkdir -p /tmp/testsuite-58-sector
    cat > /tmp/testsuite-58-sector/a.conf <<EOF
[Partition]
Type=root
SizeMaxBytes=15M
SizeMinBytes=15M
EOF
    cat > /tmp/testsuite-58-sector/b.conf <<EOF
[Partition]
Type=linux-generic
Weight=250
EOF

    cat > /tmp/testsuite-58-sector/c.conf <<EOF
[Partition]
Type=linux-generic
Weight=750
EOF

    truncate -s 100m "/tmp/testsuite-58-sector-$1.img"
    LOOP=$(losetup -b "$1" -P --show -f "/tmp/testsuite-58-sector-$1.img" )
    systemd-repart --pretty=yes --definitions=/tmp/testsuite-58-sector/ --seed=750b6cd5c4ae4012a15e7be3c29e6a47 --empty=require --dry-run=no "$LOOP"
    rm -rf /tmp/testsuite-58-sector
    sfdisk --verify "$LOOP"
    sfdisk --dump "$LOOP"
    losetup -d "$LOOP"

    rm "/tmp/testsuite-58-sector-$1.img"
}

# Valid block sizes on the Linux block layer are >= 512 and <= PAGE_SIZE, and
# must be powers of 2. Which leaves exactly four different ones to test on
# typical hardware
testsector 512
testsector 1024
testsector 2048
testsector 4096

echo OK >/testok

exit 0
