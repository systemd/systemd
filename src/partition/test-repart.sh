#!/usr/bin/env bash
set -ex

repart=$1
test -x $repart

D=$(mktemp --directory)
trap "rm -rf '$D'" EXIT INT QUIT PIPE
mkdir -p $D/definitions

SEED=e2a40bf9-73f1-4278-9160-49c031e7aef8

$repart $D/zzz --empty=create --size=1G --seed=$SEED

sfdisk -d $D/zzz | grep -v -e 'sector-size' -e '^$' >$D/empty

cmp $D/empty - <<EOF
label: gpt
label-id: EF7F7EE2-47B3-4251-B1A1-09EA8BF12D5D
device: $D/zzz
unit: sectors
first-lba: 2048
last-lba: 2097118
EOF

cat >$D/definitions/root.conf <<EOF
[Partition]
Type=root-x86-64
EOF

ln -s root.conf $D/definitions/root2.conf

cat >$D/definitions/home.conf <<EOF
[Partition]
Type=home
Label=home-first
Label=home-always-too-long-xxxxxxxxxxxxxx-%v
EOF

cat >$D/definitions/swap.conf <<EOF
[Partition]
Type=swap
SizeMaxBytes=64M
PaddingMinBytes=92M
EOF

$repart $D/zzz --dry-run=no --seed=$SEED --definitions=$D/definitions

sfdisk -d $D/zzz | grep -v -e 'sector-size' -e '^$' >$D/populated

cmp $D/populated - <<EOF
label: gpt
label-id: EF7F7EE2-47B3-4251-B1A1-09EA8BF12D5D
device: $D/zzz
unit: sectors
first-lba: 2048
last-lba: 2097118
$D/zzz1 : start=        2048, size=      591856, type=933AC7E1-2EB4-4F13-B844-0E14E2AEF915, uuid=A6005774-F558-4330-A8E5-D6D2C01C01D6, name="home-first"
$D/zzz2 : start=      593904, size=      591856, type=4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709, uuid=CE9C76EB-A8F1-40FF-813C-11DCA6C0A55B, name="root-x86-64"
$D/zzz3 : start=     1185760, size=      591864, type=4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709, uuid=AC60A837-550C-43BD-B5C4-9CB73B884E79, name="root-x86-64-2"
$D/zzz4 : start=     1777624, size=      131072, type=0657FD6D-A4AB-43C4-84E5-0933C84B4F4F, uuid=2AA78CDB-59C7-4173-AF11-C7453737A5D1, name="swap"
EOF

cat >$D/definitions/swap.conf <<EOF
[Partition]
Type=swap
SizeMaxBytes=64M
EOF

cat >$D/definitions/extra.conf <<EOF
[Partition]
Type=linux-generic
Label=custom_label
UUID=a0a1a2a3a4a5a6a7a8a9aaabacadaeaf
EOF

echo "Label=ignored_label" >>$D/definitions/home.conf
echo "UUID=b0b1b2b3b4b5b6b7b8b9babbbcbdbebf" >>$D/definitions/home.conf

$repart $D/zzz --dry-run=no --seed=$SEED --definitions=$D/definitions

sfdisk -d $D/zzz | grep -v -e 'sector-size' -e '^$' >$D/populated2

cmp $D/populated2 - <<EOF
label: gpt
label-id: EF7F7EE2-47B3-4251-B1A1-09EA8BF12D5D
device: $D/zzz
unit: sectors
first-lba: 2048
last-lba: 2097118
$D/zzz1 : start=        2048, size=      591856, type=933AC7E1-2EB4-4F13-B844-0E14E2AEF915, uuid=A6005774-F558-4330-A8E5-D6D2C01C01D6, name="home-first"
$D/zzz2 : start=      593904, size=      591856, type=4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709, uuid=CE9C76EB-A8F1-40FF-813C-11DCA6C0A55B, name="root-x86-64"
$D/zzz3 : start=     1185760, size=      591864, type=4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709, uuid=AC60A837-550C-43BD-B5C4-9CB73B884E79, name="root-x86-64-2"
$D/zzz4 : start=     1777624, size=      131072, type=0657FD6D-A4AB-43C4-84E5-0933C84B4F4F, uuid=2AA78CDB-59C7-4173-AF11-C7453737A5D1, name="swap"
$D/zzz5 : start=     1908696, size=      188416, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, uuid=A0A1A2A3-A4A5-A6A7-A8A9-AAABACADAEAF, name="custom_label"
EOF

$repart $D/zzz --size=2G --dry-run=no --seed=$SEED --definitions=$D/definitions

sfdisk -d $D/zzz | grep -v -e 'sector-size' -e '^$' >$D/populated3

cmp $D/populated3 - <<EOF
label: gpt
label-id: EF7F7EE2-47B3-4251-B1A1-09EA8BF12D5D
device: $D/zzz
unit: sectors
first-lba: 2048
last-lba: 4194270
$D/zzz1 : start=        2048, size=      591856, type=933AC7E1-2EB4-4F13-B844-0E14E2AEF915, uuid=A6005774-F558-4330-A8E5-D6D2C01C01D6, name="home-first"
$D/zzz2 : start=      593904, size=      591856, type=4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709, uuid=CE9C76EB-A8F1-40FF-813C-11DCA6C0A55B, name="root-x86-64"
$D/zzz3 : start=     1185760, size=      591864, type=4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709, uuid=AC60A837-550C-43BD-B5C4-9CB73B884E79, name="root-x86-64-2"
$D/zzz4 : start=     1777624, size=      131072, type=0657FD6D-A4AB-43C4-84E5-0933C84B4F4F, uuid=2AA78CDB-59C7-4173-AF11-C7453737A5D1, name="swap"
$D/zzz5 : start=     1908696, size=     2285568, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, uuid=A0A1A2A3-A4A5-A6A7-A8A9-AAABACADAEAF, name="custom_label"
EOF

dd if=/dev/urandom of=$D/block-copy bs=4096 count=10240

cat >$D/definitions/extra2.conf <<EOF
[Partition]
Type=linux-generic
Label=block-copy
UUID=2a1d97e1d0a346cca26eadc643926617
CopyBlocks=$D/block-copy
EOF

$repart $D/zzz --size=3G --dry-run=no --seed=$SEED --definitions=$D/definitions

sfdisk -d $D/zzz | grep -v -e 'sector-size' -e '^$' >$D/populated4

cmp $D/populated4 - <<EOF
label: gpt
label-id: EF7F7EE2-47B3-4251-B1A1-09EA8BF12D5D
device: $D/zzz
unit: sectors
first-lba: 2048
last-lba: 6291422
$D/zzz1 : start=        2048, size=      591856, type=933AC7E1-2EB4-4F13-B844-0E14E2AEF915, uuid=A6005774-F558-4330-A8E5-D6D2C01C01D6, name="home-first"
$D/zzz2 : start=      593904, size=      591856, type=4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709, uuid=CE9C76EB-A8F1-40FF-813C-11DCA6C0A55B, name="root-x86-64"
$D/zzz3 : start=     1185760, size=      591864, type=4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709, uuid=AC60A837-550C-43BD-B5C4-9CB73B884E79, name="root-x86-64-2"
$D/zzz4 : start=     1777624, size=      131072, type=0657FD6D-A4AB-43C4-84E5-0933C84B4F4F, uuid=2AA78CDB-59C7-4173-AF11-C7453737A5D1, name="swap"
$D/zzz5 : start=     1908696, size=     2285568, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, uuid=A0A1A2A3-A4A5-A6A7-A8A9-AAABACADAEAF, name="custom_label"
$D/zzz6 : start=     4194264, size=     2097152, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, uuid=2A1D97E1-D0A3-46CC-A26E-ADC643926617, name="block-copy"
EOF

cmp --bytes=41943040 --ignore-initial=0:$((512*4194264)) $D/block-copy $D/zzz
