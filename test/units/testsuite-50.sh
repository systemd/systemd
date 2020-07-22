#!/usr/bin/env bash
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
set -ex
set -o pipefail

export SYSTEMD_LOG_LEVEL=debug

cleanup()
{
    if [ -z "${image_dir}" ]; then
        return
    fi
    rm -rf "${image_dir}"
}

cd /tmp

image_dir="$(mktemp -d -t -p /tmp tmp.XXXXXX)"
if [ -z "${image_dir}" ] || [ ! -d "${image_dir}" ]; then
    echo "mktemp under /tmp failed"
    exit 1
fi

trap cleanup EXIT

cp /usr/share/minimal.* "${image_dir}/"
image="${image_dir}/minimal"
roothash="$(cat ${image}.roothash)"

/usr/lib/systemd/systemd-dissect ${image}.raw | grep -q -F "Found read-only 'root' partition of type squashfs with verity"
/usr/lib/systemd/systemd-dissect ${image}.raw | grep -q -F "MARKER=1"
/usr/lib/systemd/systemd-dissect ${image}.raw | grep -q -F -f /usr/lib/os-release

mv ${image}.verity ${image}.fooverity
mv ${image}.roothash ${image}.foohash
/usr/lib/systemd/systemd-dissect ${image}.raw --root-hash=${roothash} --verity-data=${image}.fooverity | grep -q -F "Found read-only 'root' partition of type squashfs with verity"
/usr/lib/systemd/systemd-dissect ${image}.raw --root-hash=${roothash} --verity-data=${image}.fooverity | grep -q -F "MARKER=1"
/usr/lib/systemd/systemd-dissect ${image}.raw --root-hash=${roothash} --verity-data=${image}.fooverity | grep -q -F -f /usr/lib/os-release
mv ${image}.fooverity ${image}.verity
mv ${image}.foohash ${image}.roothash

mkdir -p ${image_dir}/mount ${image_dir}/mount2
/usr/lib/systemd/systemd-dissect --mount ${image}.raw ${image_dir}/mount
cat ${image_dir}/mount/usr/lib/os-release | grep -q -F -f /usr/lib/os-release
cat ${image_dir}/mount/etc/os-release | grep -q -F -f /usr/lib/os-release
cat ${image_dir}/mount/usr/lib/os-release | grep -q -F "MARKER=1"
# Verity volume should be shared (opened only once)
/usr/lib/systemd/systemd-dissect --mount ${image}.raw ${image_dir}/mount2
verity_count=$(ls -1 /dev/mapper/ | grep -c verity)
# In theory we should check that count is exactly one. In practice, libdevmapper
# randomly and unpredictably fails with an unhelpful EINVAL when a device is open
# (and even mounted and in use), so best-effort is the most we can do for now
if [ ${verity_count} -lt 1 ]; then
    echo "Verity device ${image}.raw not found in /dev/mapper/"
    exit 1
fi
umount ${image_dir}/mount
umount ${image_dir}/mount2

systemd-run -t --property RootImage=${image}.raw /usr/bin/cat /usr/lib/os-release | grep -q -F "MARKER=1"
mv ${image}.verity ${image}.fooverity
mv ${image}.roothash ${image}.foohash
systemd-run -t --property RootImage=${image}.raw --property RootHash=${image}.foohash --property RootVerity=${image}.fooverity /usr/bin/cat /usr/lib/os-release | grep -q -F "MARKER=1"
systemd-run -t --property RootImage=${image}.raw --property RootHash=${roothash} --property RootVerity=${image}.fooverity /usr/bin/cat /usr/lib/os-release | grep -q -F "MARKER=1"
mv ${image}.fooverity ${image}.verity
mv ${image}.foohash ${image}.roothash

# Make a GPT disk on the fly, with the squashfs as partition 1 and the verity hash tree as partition 2
machine="$(uname -m)"
if [ "${machine}" = "x86_64" ]; then
    root_guid=4f68bce3-e8cd-4db1-96e7-fbcaf984b709
    verity_guid=2c7357ed-ebd2-46d9-aec1-23d437ec2bf5
elif [ "${machine}" = "i386" ] || [ "${machine}" = "i686" ] || [ "${machine}" = "x86" ]; then
    root_guid=44479540-f297-41b2-9af7-d131d5f0458a
    verity_guid=d13c5d3b-b5d1-422a-b29f-9454fdc89d76
elif [ "${machine}" = "aarch64" ] || [ "${machine}" = "aarch64_be" ] || [ "${machine}" = "armv8b" ] || [ "${machine}" = "armv8l" ]; then
    root_guid=b921b045-1df0-41c3-af44-4c6f280d3fae
    verity_guid=df3300ce-d69f-4c92-978c-9bfb0f38d820
elif [ "${machine}" = "arm" ]; then
    root_guid=69dad710-2ce4-4e3c-b16c-21a1d49abed3
    verity_guid=7386cdf2-203c-47a9-a498-f2ecce45a2d6
elif [ "${machine}" = "ia64" ]; then
    root_guid=993d8d3d-f80e-4225-855a-9daf8ed7ea97
    verity_guid=86ed10d5-b607-45bb-8957-d350f23d0571
else
    echo "Unexpected uname -m: ${machine} in testsuite-50.sh, please fix me"
    exit 1
fi
# du rounds up to block size, which is more helpful for partitioning
root_size="$(du -k ${image}.raw | cut -f1)"
verity_size="$(du -k ${image}.verity | cut -f1)"
# 4MB seems to be the minimum size blkid will accept, below that probing fails
dd if=/dev/zero of=${image}.gpt bs=512 count=$((8192+${root_size}*2+${verity_size}*2))
# sfdisk seems unhappy if the size overflows into the next unit, eg: 1580KiB will be interpreted as 1MiB
# so do some basic rounding up if the minimal image is more than 1 MB
if [ ${root_size} -ge 1024 ]; then
    root_size="$((${root_size}/1024 + 1))MiB"
else
    root_size="${root_size}KiB"
fi
verity_size="${verity_size}KiB"
uuid="$(head -c 32 ${image}.roothash | cut -c -8)-$(head -c 32 ${image}.roothash | cut -c 9-12)-$(head -c 32 ${image}.roothash | cut -c 13-16)-$(head -c 32 ${image}.roothash | cut -c 17-20)-$(head -c 32 ${image}.roothash | cut -c 21-)"
echo -e "label: gpt\nsize=${root_size}, type=${root_guid}, uuid=${uuid}" | sfdisk ${image}.gpt
uuid="$(tail -c 32 ${image}.roothash | cut -c -8)-$(tail -c 32 ${image}.roothash | cut -c 9-12)-$(tail -c 32 ${image}.roothash | cut -c 13-16)-$(tail -c 32 ${image}.roothash | cut -c 17-20)-$(tail -c 32 ${image}.roothash | cut -c 21-)"
echo -e "size=${verity_size}, type=${verity_guid}, uuid=${uuid}" | sfdisk ${image}.gpt --append
sfdisk --part-label ${image}.gpt 1 "Root Partition"
sfdisk --part-label ${image}.gpt 2 "Verity Partition"
loop="$(losetup --show -P -f ${image}.gpt)"
dd if=${image}.raw of=${loop}p1
dd if=${image}.verity of=${loop}p2
losetup -d ${loop}

/usr/lib/systemd/systemd-dissect --root-hash ${roothash} ${image}.gpt | grep -q "Found read-only 'root' partition (UUID $(head -c 32 ${image}.roothash)) of type squashfs for .* with verity on partition #1"
/usr/lib/systemd/systemd-dissect --root-hash ${roothash} ${image}.gpt | grep -q "Found read-only 'root-verity' partition (UUID $(tail -c 32 ${image}.roothash)) of type DM_verity_hash for .* on partition #2"
/usr/lib/systemd/systemd-dissect --root-hash ${roothash} ${image}.gpt | grep -q -F "MARKER=1"
/usr/lib/systemd/systemd-dissect --root-hash ${roothash} ${image}.gpt | grep -q -F -f /usr/lib/os-release

/usr/lib/systemd/systemd-dissect --root-hash ${roothash} --mount ${image}.gpt ${image_dir}/mount
cat ${image_dir}/mount/usr/lib/os-release | grep -q -F -f /usr/lib/os-release
cat ${image_dir}/mount/etc/os-release | grep -q -F -f /usr/lib/os-release
cat ${image_dir}/mount/usr/lib/os-release | grep -q -F "MARKER=1"
umount ${image_dir}/mount

systemd-run -t --property RootImage=${image}.gpt --property RootHash=${roothash} /usr/bin/cat /usr/lib/os-release | grep -q -F "MARKER=1"

echo OK > /testok

exit 0
