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

cp /usr/share/minimal* "${image_dir}/"
image="${image_dir}/minimal_0"
roothash="$(cat ${image}.roothash)"

os_release=$(test -e /etc/os-release && echo /etc/os-release || echo /usr/lib/os-release)

systemd-dissect --json=short ${image}.raw | grep -q -F '{"rw":"ro","designator":"root","partition_uuid":null,"fstype":"squashfs","architecture":null,"verity":"external"'
systemd-dissect ${image}.raw | grep -q -F "MARKER=1"
systemd-dissect ${image}.raw | grep -q -F -f $os_release

mv ${image}.verity ${image}.fooverity
mv ${image}.roothash ${image}.foohash
systemd-dissect --json=short ${image}.raw --root-hash=${roothash} --verity-data=${image}.fooverity | grep -q -F '{"rw":"ro","designator":"root","partition_uuid":null,"fstype":"squashfs","architecture":null,"verity":"external"'
systemd-dissect ${image}.raw --root-hash=${roothash} --verity-data=${image}.fooverity | grep -q -F "MARKER=1"
systemd-dissect ${image}.raw --root-hash=${roothash} --verity-data=${image}.fooverity | grep -q -F -f $os_release
mv ${image}.fooverity ${image}.verity
mv ${image}.foohash ${image}.roothash

mkdir -p ${image_dir}/mount ${image_dir}/mount2
systemd-dissect --mount ${image}.raw ${image_dir}/mount
cat ${image_dir}/mount/usr/lib/os-release | grep -q -F -f $os_release
cat ${image_dir}/mount/etc/os-release | grep -q -F -f $os_release
cat ${image_dir}/mount/usr/lib/os-release | grep -q -F "MARKER=1"
# Verity volume should be shared (opened only once)
systemd-dissect --mount ${image}.raw ${image_dir}/mount2
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

systemd-run -t -p RootImage=${image}.raw cat /usr/lib/os-release | grep -q -F "MARKER=1"
mv ${image}.verity ${image}.fooverity
mv ${image}.roothash ${image}.foohash
systemd-run -t -p RootImage=${image}.raw -p RootHash=${image}.foohash -p RootVerity=${image}.fooverity cat /usr/lib/os-release | grep -q -F "MARKER=1"
# Let's use the long option name just here as a test
systemd-run -t --property RootImage=${image}.raw --property RootHash=${roothash} --property RootVerity=${image}.fooverity cat /usr/lib/os-release | grep -q -F "MARKER=1"
mv ${image}.fooverity ${image}.verity
mv ${image}.foohash ${image}.roothash

# Make a GPT disk on the fly, with the squashfs as partition 1 and the verity hash tree as partition 2
machine="$(uname -m)"
if [ "${machine}" = "x86_64" ]; then
    root_guid=4f68bce3-e8cd-4db1-96e7-fbcaf984b709
    verity_guid=2c7357ed-ebd2-46d9-aec1-23d437ec2bf5
    architecture="x86-64"
elif [ "${machine}" = "i386" ] || [ "${machine}" = "i686" ] || [ "${machine}" = "x86" ]; then
    root_guid=44479540-f297-41b2-9af7-d131d5f0458a
    verity_guid=d13c5d3b-b5d1-422a-b29f-9454fdc89d76
    architecture="x86"
elif [ "${machine}" = "aarch64" ] || [ "${machine}" = "aarch64_be" ] || [ "${machine}" = "armv8b" ] || [ "${machine}" = "armv8l" ]; then
    root_guid=b921b045-1df0-41c3-af44-4c6f280d3fae
    verity_guid=df3300ce-d69f-4c92-978c-9bfb0f38d820
    architecture="arm64"
elif [ "${machine}" = "arm" ]; then
    root_guid=69dad710-2ce4-4e3c-b16c-21a1d49abed3
    verity_guid=7386cdf2-203c-47a9-a498-f2ecce45a2d6
    architecture="arm"
elif [ "${machine}" = "ia64" ]; then
    root_guid=993d8d3d-f80e-4225-855a-9daf8ed7ea97
    verity_guid=86ed10d5-b607-45bb-8957-d350f23d0571
    architecture="ia64"
elif [ "${machine}" = "ppc64le" ]; then
    # There's no support of PPC in the discoverable partitions specification yet, so skip the rest for now
    echo OK >/testok
    exit 0
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
verity_size="$((${verity_size} * 2))KiB"
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

# Derive partition UUIDs from root hash, in UUID syntax
ROOT_UUID=$(systemd-id128 -u show $(head -c 32 ${image}.roothash) -u | tail -n 1 | cut -b 6-)
VERITY_UUID=$(systemd-id128 -u show $(tail -c 32 ${image}.roothash) -u | tail -n 1 | cut -b 6-)

systemd-dissect --json=short --root-hash ${roothash} ${image}.gpt | grep -q '{"rw":"ro","designator":"root","partition_uuid":"'$ROOT_UUID'","fstype":"squashfs","architecture":"'$architecture'","verity":"yes","node":'
systemd-dissect --json=short --root-hash ${roothash} ${image}.gpt | grep -q '{"rw":"ro","designator":"root-verity","partition_uuid":"'$VERITY_UUID'","fstype":"DM_verity_hash","architecture":"'$architecture'","verity":null,"node":'
systemd-dissect --root-hash ${roothash} ${image}.gpt | grep -q -F "MARKER=1"
systemd-dissect --root-hash ${roothash} ${image}.gpt | grep -q -F -f $os_release

systemd-dissect --root-hash ${roothash} --mount ${image}.gpt ${image_dir}/mount
cat ${image_dir}/mount/usr/lib/os-release | grep -q -F -f $os_release
cat ${image_dir}/mount/etc/os-release | grep -q -F -f $os_release
cat ${image_dir}/mount/usr/lib/os-release | grep -q -F "MARKER=1"
umount ${image_dir}/mount

# add explicit -p MountAPIVFS=yes once to test the parser
systemd-run -t -p RootImage=${image}.gpt -p RootHash=${roothash} -p MountAPIVFS=yes cat /usr/lib/os-release | grep -q -F "MARKER=1"

systemd-run -t -p RootImage=${image}.raw -p RootImageOptions="root:nosuid,dev home:ro,dev ro,noatime" mount | grep -F "squashfs" | grep -q -F "nosuid"
systemd-run -t -p RootImage=${image}.gpt -p RootImageOptions="root:ro,noatime root:ro,dev" mount | grep -F "squashfs" | grep -q -F "noatime"

mkdir -p mkdir -p ${image_dir}/result
cat >/run/systemd/system/testservice-50a.service <<EOF
[Service]
Type=oneshot
ExecStart=bash -c "mount >/run/result/a"
BindPaths=${image_dir}/result:/run/result
TemporaryFileSystem=/run
RootImage=${image}.raw
RootImageOptions=root:ro,noatime home:ro,dev relatime,dev
RootImageOptions=nosuid,dev
EOF
systemctl start testservice-50a.service
grep -F "squashfs" ${image_dir}/result/a | grep -q -F "noatime"
grep -F "squashfs" ${image_dir}/result/a | grep -q -F -v "nosuid"

cat >/run/systemd/system/testservice-50b.service <<EOF
[Service]
Type=oneshot
ExecStart=bash -c "mount >/run/result/b"
BindPaths=${image_dir}/result:/run/result
TemporaryFileSystem=/run
RootImage=${image}.gpt
RootImageOptions=root:ro,noatime,nosuid home:ro,dev nosuid,dev
RootImageOptions=home:ro,dev nosuid,dev,%%foo
# this is the default, but let's specify once to test the parser
MountAPIVFS=yes
EOF
systemctl start testservice-50b.service
grep -F "squashfs" ${image_dir}/result/b | grep -q -F "noatime"

# Check that specifier escape is applied %%foo → %foo
busctl get-property org.freedesktop.systemd1 /org/freedesktop/systemd1/unit/testservice_2d50b_2eservice org.freedesktop.systemd1.Service RootImageOptions | grep -F "nosuid,dev,%foo"

# Now do some checks with MountImages, both by itself, with options and in combination with RootImage, and as single FS or GPT image
systemd-run -t -p MountImages="${image}.gpt:/run/img1 ${image}.raw:/run/img2" cat /run/img1/usr/lib/os-release | grep -q -F "MARKER=1"
systemd-run -t -p MountImages="${image}.gpt:/run/img1 ${image}.raw:/run/img2" cat /run/img2/usr/lib/os-release | grep -q -F "MARKER=1"
systemd-run -t -p MountImages="${image}.gpt:/run/img1 ${image}.raw:/run/img2:nosuid,dev" mount | grep -F "squashfs" | grep -q -F "nosuid"
systemd-run -t -p MountImages="${image}.gpt:/run/img1:root:nosuid ${image}.raw:/run/img2:home:suid" mount | grep -F "squashfs" | grep -q -F "nosuid"
systemd-run -t -p MountImages="${image}.raw:/run/img2\:3" cat /run/img2:3/usr/lib/os-release | grep -q -F "MARKER=1"
systemd-run -t -p MountImages="${image}.raw:/run/img2\:3:nosuid" mount | grep -F "squashfs" | grep -q -F "nosuid"
systemd-run -t -p TemporaryFileSystem=/run -p RootImage=${image}.raw -p MountImages="${image}.gpt:/run/img1 ${image}.raw:/run/img2" cat /usr/lib/os-release | grep -q -F "MARKER=1"
systemd-run -t -p TemporaryFileSystem=/run -p RootImage=${image}.raw -p MountImages="${image}.gpt:/run/img1 ${image}.raw:/run/img2" cat /run/img1/usr/lib/os-release | grep -q -F "MARKER=1"
systemd-run -t -p TemporaryFileSystem=/run -p RootImage=${image}.gpt -p RootHash=${roothash} -p MountImages="${image}.gpt:/run/img1 ${image}.raw:/run/img2" cat /run/img2/usr/lib/os-release | grep -q -F "MARKER=1"
cat >/run/systemd/system/testservice-50c.service <<EOF
[Service]
MountAPIVFS=yes
TemporaryFileSystem=/run
RootImage=${image}.raw
MountImages=${image}.gpt:/run/img1:root:noatime:home:relatime
MountImages=${image}.raw:/run/img2\:3:nosuid
ExecStart=bash -c "cat /run/img1/usr/lib/os-release >/run/result/c"
ExecStart=bash -c "cat /run/img2:3/usr/lib/os-release >>/run/result/c"
ExecStart=bash -c "mount >>/run/result/c"
BindPaths=${image_dir}/result:/run/result
Type=oneshot
EOF
systemctl start testservice-50c.service
grep -q -F "MARKER=1" ${image_dir}/result/c
grep -F "squashfs" ${image_dir}/result/c | grep -q -F "noatime"
grep -F "squashfs" ${image_dir}/result/c | grep -q -F -v "nosuid"

# Adding a new mounts at runtime works if the unit is in the active state,
# so use Type=notify to make sure there's no race condition in the test
cat > /run/systemd/system/testservice-50d.service <<EOF
[Service]
RuntimeMaxSec=300
Type=notify
RemainAfterExit=yes
MountAPIVFS=yes
PrivateTmp=yes
ExecStart=/bin/sh -c 'systemd-notify --ready; while ! grep -q -F MARKER /tmp/img/usr/lib/os-release; do sleep 0.1; done; mount | grep -F "/tmp/img" | grep -q -F "nosuid"'
EOF
systemctl start testservice-50d.service

systemctl mount-image --mkdir testservice-50d.service ${image}.raw /tmp/img root:nosuid

while systemctl show -P SubState testservice-50d.service | grep -q running
do
    sleep 0.1
done

systemctl is-active testservice-50d.service

# ExtensionImages will set up an overlay
systemd-run -t --property ExtensionImages=/usr/share/app0.raw --property RootImage=${image}.raw cat /opt/script0.sh | grep -q -F "extension-release.app0"
systemd-run -t --property ExtensionImages=/usr/share/app0.raw --property RootImage=${image}.raw cat /usr/lib/systemd/system/some_file | grep -q -F "MARKER=1"
systemd-run -t --property ExtensionImages="/usr/share/app0.raw /usr/share/app1.raw" --property RootImage=${image}.raw cat /opt/script0.sh | grep -q -F "extension-release.app0"
systemd-run -t --property ExtensionImages="/usr/share/app0.raw /usr/share/app1.raw" --property RootImage=${image}.raw cat /usr/lib/systemd/system/some_file | grep -q -F "MARKER=1"
systemd-run -t --property ExtensionImages="/usr/share/app0.raw /usr/share/app1.raw" --property RootImage=${image}.raw cat /opt/script1.sh | grep -q -F "extension-release.app1"
systemd-run -t --property ExtensionImages="/usr/share/app0.raw /usr/share/app1.raw" --property RootImage=${image}.raw cat /usr/lib/systemd/system/other_file | grep -q -F "MARKER=1"
cat >/run/systemd/system/testservice-50e.service <<EOF
[Service]
MountAPIVFS=yes
TemporaryFileSystem=/run
RootImage=${image}.raw
ExtensionImages=/usr/share/app0.raw /usr/share/app1.raw:nosuid
# Relevant only for sanitizer runs
UnsetEnvironment=LD_PRELOAD
ExecStart=/bin/bash -c '/opt/script0.sh | grep ID'
ExecStart=/bin/bash -c '/opt/script1.sh | grep ID'
Type=oneshot
RemainAfterExit=yes
EOF
systemctl start testservice-50e.service
systemctl is-active testservice-50e.service

echo OK >/testok

exit 0
