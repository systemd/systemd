#!/usr/bin/env bash
set -ex

# Check if repart is installed, and if it isn't bail out early instead of failing
if ! test -x /usr/bin/systemd-repart ; then
    echo OK > /testok
    exit 0
fi

systemd-analyze log-level debug

truncate -s 1G /tmp/zzz

SEED=e2a40bf9-73f1-4278-9160-49c031e7aef8

systemd-repart /tmp/zzz --empty=force --dry-run=no --seed=$SEED

sfdisk -d /tmp/zzz | grep -v -e 'sector-size' -e '^$' > /tmp/empty

cmp /tmp/empty - <<EOF
label: gpt
label-id: EF7F7EE2-47B3-4251-B1A1-09EA8BF12D5D
device: /tmp/zzz
unit: sectors
first-lba: 2048
last-lba: 2097118
EOF

mkdir /tmp/definitions

cat > /tmp/definitions/root.conf <<EOF
[Partition]
Type=root
EOF

ln -s root.conf /tmp/definitions/root2.conf

cat > /tmp/definitions/home.conf <<EOF
[Partition]
Type=home
EOF

cat > /tmp/definitions/swap.conf <<EOF
[Partition]
Type=swap
SizeMaxBytes=64M
PaddingMinBytes=92M
EOF

systemd-repart /tmp/zzz --dry-run=no --seed=$SEED --definitions=/tmp/definitions

sfdisk -d /tmp/zzz | grep -v -e 'sector-size' -e '^$' > /tmp/populated

cmp /tmp/populated - <<EOF
label: gpt
label-id: EF7F7EE2-47B3-4251-B1A1-09EA8BF12D5D
device: /tmp/zzz
unit: sectors
first-lba: 2048
last-lba: 2097118
/tmp/zzz1 : start=        2048, size=      591856, type=933AC7E1-2EB4-4F13-B844-0E14E2AEF915, uuid=A6005774-F558-4330-A8E5-D6D2C01C01D6, name="home"
/tmp/zzz2 : start=      593904, size=      591856, type=4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709, uuid=CE9C76EB-A8F1-40FF-813C-11DCA6C0A55B, name="root-x86-64"
/tmp/zzz3 : start=     1185760, size=      591864, type=4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709, uuid=AC60A837-550C-43BD-B5C4-9CB73B884E79, name="root-x86-64-2"
/tmp/zzz4 : start=     1777624, size=      131072, type=0657FD6D-A4AB-43C4-84E5-0933C84B4F4F, uuid=2AA78CDB-59C7-4173-AF11-C7453737A5D1, name="swap"
EOF

cat > /tmp/definitions/swap.conf <<EOF
[Partition]
Type=swap
SizeMaxBytes=64M
EOF

cat > /tmp/definitions/extra.conf <<EOF
[Partition]
Type=linux-generic
EOF

systemd-repart /tmp/zzz --dry-run=no --seed=$SEED --definitions=/tmp/definitions

sfdisk -d /tmp/zzz | grep -v -e 'sector-size' -e '^$' > /tmp/populated2

cmp /tmp/populated2 - <<EOF
label: gpt
label-id: EF7F7EE2-47B3-4251-B1A1-09EA8BF12D5D
device: /tmp/zzz
unit: sectors
first-lba: 2048
last-lba: 2097118
/tmp/zzz1 : start=        2048, size=      591856, type=933AC7E1-2EB4-4F13-B844-0E14E2AEF915, uuid=A6005774-F558-4330-A8E5-D6D2C01C01D6, name="home"
/tmp/zzz2 : start=      593904, size=      591856, type=4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709, uuid=CE9C76EB-A8F1-40FF-813C-11DCA6C0A55B, name="root-x86-64"
/tmp/zzz3 : start=     1185760, size=      591864, type=4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709, uuid=AC60A837-550C-43BD-B5C4-9CB73B884E79, name="root-x86-64-2"
/tmp/zzz4 : start=     1777624, size=      131072, type=0657FD6D-A4AB-43C4-84E5-0933C84B4F4F, uuid=2AA78CDB-59C7-4173-AF11-C7453737A5D1, name="swap"
/tmp/zzz5 : start=     1908696, size=      188416, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, uuid=03477476-06AD-44E8-9EF4-BC2BD7771289, name="linux-generic"
EOF

truncate -s 2G /tmp/zzz

systemd-repart /tmp/zzz --dry-run=no --seed=$SEED --definitions=/tmp/definitions

sfdisk -d /tmp/zzz | grep -v -e 'sector-size' -e '^$' > /tmp/populated3

cmp /tmp/populated3 - <<EOF
label: gpt
label-id: EF7F7EE2-47B3-4251-B1A1-09EA8BF12D5D
device: /tmp/zzz
unit: sectors
first-lba: 2048
last-lba: 4194270
/tmp/zzz1 : start=        2048, size=      591856, type=933AC7E1-2EB4-4F13-B844-0E14E2AEF915, uuid=A6005774-F558-4330-A8E5-D6D2C01C01D6, name="home"
/tmp/zzz2 : start=      593904, size=      591856, type=4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709, uuid=CE9C76EB-A8F1-40FF-813C-11DCA6C0A55B, name="root-x86-64"
/tmp/zzz3 : start=     1185760, size=      591864, type=4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709, uuid=AC60A837-550C-43BD-B5C4-9CB73B884E79, name="root-x86-64-2"
/tmp/zzz4 : start=     1777624, size=      131072, type=0657FD6D-A4AB-43C4-84E5-0933C84B4F4F, uuid=2AA78CDB-59C7-4173-AF11-C7453737A5D1, name="swap"
/tmp/zzz5 : start=     1908696, size=     2285568, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, uuid=03477476-06AD-44E8-9EF4-BC2BD7771289, name="linux-generic"
EOF

systemd-analyze log-level info

echo OK > /testok

exit 0
