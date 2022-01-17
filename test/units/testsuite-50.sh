#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
set -eux
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
roothash="$(cat "${image}.roothash")"

os_release="$(test -e /etc/os-release && echo /etc/os-release || echo /usr/lib/os-release)"

systemd-dissect --json=short "${image}.raw" | grep -q -F '{"rw":"ro","designator":"root","partition_uuid":null,"partition_label":null,"fstype":"squashfs","architecture":null,"verity":"external"'
systemd-dissect "${image}.raw" | grep -q -F "MARKER=1"
systemd-dissect "${image}.raw" | grep -q -F -f <(sed 's/"//g' "$os_release")

mv "${image}.verity" "${image}.fooverity"
mv "${image}.roothash" "${image}.foohash"
systemd-dissect --json=short "${image}.raw" --root-hash="${roothash}" --verity-data="${image}.fooverity" | grep -q -F '{"rw":"ro","designator":"root","partition_uuid":null,"partition_label":null,"fstype":"squashfs","architecture":null,"verity":"external"'
systemd-dissect "${image}.raw" --root-hash="${roothash}" --verity-data="${image}.fooverity" | grep -q -F "MARKER=1"
systemd-dissect "${image}.raw" --root-hash="${roothash}" --verity-data="${image}.fooverity" | grep -q -F -f <(sed 's/"//g' "$os_release")
mv "${image}.fooverity" "${image}.verity"
mv "${image}.foohash" "${image}.roothash"

mkdir -p "${image_dir}/mount" "${image_dir}/mount2"
systemd-dissect --mount "${image}.raw" "${image_dir}/mount"
grep -q -F -f "$os_release" "${image_dir}/mount/usr/lib/os-release"
grep -q -F -f "$os_release" "${image_dir}/mount/etc/os-release"
grep -q -F "MARKER=1" "${image_dir}/mount/usr/lib/os-release"
# Verity volume should be shared (opened only once)
systemd-dissect --mount "${image}.raw" "${image_dir}/mount2"
verity_count=$(find /dev/mapper/ -name "*verity*" | wc -l)
# In theory we should check that count is exactly one. In practice, libdevmapper
# randomly and unpredictably fails with an unhelpful EINVAL when a device is open
# (and even mounted and in use), so best-effort is the most we can do for now
if [ "${verity_count}" -lt 1 ]; then
    echo "Verity device ${image}.raw not found in /dev/mapper/"
    exit 1
fi
umount "${image_dir}/mount"
umount "${image_dir}/mount2"

systemd-run -P -p RootImage="${image}.raw" cat /usr/lib/os-release | grep -q -F "MARKER=1"
mv "${image}.verity" "${image}.fooverity"
mv "${image}.roothash" "${image}.foohash"
systemd-run -P -p RootImage="${image}.raw" -p RootHash="${image}.foohash" -p RootVerity="${image}.fooverity" cat /usr/lib/os-release | grep -q -F "MARKER=1"
# Let's use the long option name just here as a test
systemd-run -P --property RootImage="${image}.raw" --property RootHash="${roothash}" --property RootVerity="${image}.fooverity" cat /usr/lib/os-release | grep -q -F "MARKER=1"
mv "${image}.fooverity" "${image}.verity"
mv "${image}.foohash" "${image}.roothash"

# Make a GPT disk on the fly, with the squashfs as partition 1 and the verity hash tree as partition 2
machine="$(uname -m)"
if [ "${machine}" = "x86_64" ]; then
    root_guid=4f68bce3-e8cd-4db1-96e7-fbcaf984b709
    verity_guid=2c7357ed-ebd2-46d9-aec1-23d437ec2bf5
    signature_guid=41092b05-9fc8-4523-994f-2def0408b176
    architecture="x86-64"
elif [ "${machine}" = "i386" ] || [ "${machine}" = "i686" ] || [ "${machine}" = "x86" ]; then
    root_guid=44479540-f297-41b2-9af7-d131d5f0458a
    verity_guid=d13c5d3b-b5d1-422a-b29f-9454fdc89d76
    signature_guid=5996fc05-109c-48de-808b-23fa0830b676
    architecture="x86"
elif [ "${machine}" = "aarch64" ] || [ "${machine}" = "aarch64_be" ] || [ "${machine}" = "armv8b" ] || [ "${machine}" = "armv8l" ]; then
    root_guid=b921b045-1df0-41c3-af44-4c6f280d3fae
    verity_guid=df3300ce-d69f-4c92-978c-9bfb0f38d820
    signature_guid=6db69de6-29f4-4758-a7a5-962190f00ce3
    architecture="arm64"
elif [ "${machine}" = "arm" ]; then
    root_guid=69dad710-2ce4-4e3c-b16c-21a1d49abed3
    verity_guid=7386cdf2-203c-47a9-a498-f2ecce45a2d6
    signature_guid=42b0455f-eb11-491d-98d3-56145ba9d037
    architecture="arm"
elif [ "${machine}" = "loongarch64" ]; then
    root_guid=77055800-792c-4f94-b39a-98c91b762bb6
    verity_guid=f3393b22-e9af-4613-a948-9d3bfbd0c535
    signature_guid=5afb67eb-ecc8-4f85-ae8e-ac1e7c50e7d0
    architecture="loongarch64"
elif [ "${machine}" = "ia64" ]; then
    root_guid=993d8d3d-f80e-4225-855a-9daf8ed7ea97
    verity_guid=86ed10d5-b607-45bb-8957-d350f23d0571
    signature_guid=e98b36ee-32ba-4882-9b12-0ce14655f46a
    architecture="ia64"
elif [ "${machine}" = "s390x" ]; then
    root_guid=5eead9a9-fe09-4a1e-a1d7-520d00531306
    verity_guid=b325bfbe-c7be-4ab8-8357-139e652d2f6b
    signature_guid=c80187a5-73a3-491a-901a-017c3fa953e9
    architecture="s390x"
elif [ "${machine}" = "ppc64le" ]; then
    root_guid=c31c45e6-3f39-412e-80fb-4809c4980599
    verity_guid=906bd944-4589-4aae-a4e4-dd983917446a
    signature_guid=d4a236e7-e873-4c07-bf1d-bf6cf7f1c3c6
    architecture="ppc64-le"
else
    echo "Unexpected uname -m: ${machine} in testsuite-50.sh, please fix me"
    exit 1
fi
# du rounds up to block size, which is more helpful for partitioning
root_size="$(du -k "${image}.raw" | cut -f1)"
verity_size="$(du -k "${image}.verity" | cut -f1)"
signature_size=4
# 4MB seems to be the minimum size blkid will accept, below that probing fails
dd if=/dev/zero of="${image}.gpt" bs=512 count=$((8192+root_size*2+verity_size*2+signature_size*2))
# sfdisk seems unhappy if the size overflows into the next unit, eg: 1580KiB will be interpreted as 1MiB
# so do some basic rounding up if the minimal image is more than 1 MB
if [ "${root_size}" -ge 1024 ]; then
    root_size="$((root_size/1024 + 1))MiB"
else
    root_size="${root_size}KiB"
fi
verity_size="$((verity_size * 2))KiB"
signature_size="$((signature_size * 2))KiB"

HAVE_OPENSSL=0
if systemctl --version | grep -q -- +OPENSSL ; then
    # The openssl binary is installed conditionally.
    # If we have OpenSSL support enabled and openssl is missing, fail early
    # with a proper error message.
    if ! command -v openssl >/dev/null 2>&1; then
        echo "openssl missing" >/failed
        exit 1
    fi
    HAVE_OPENSSL=1
    # Unfortunately OpenSSL insists on reading some config file, hence provide one with mostly placeholder contents
    cat >> "${image}.openssl.cnf" <<EOF
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

    # Create key pair
    openssl req -config "${image}.openssl.cnf" -new -x509 -newkey rsa:1024 -keyout "${image}.key" -out "${image}.crt" -days 365 -nodes
    # Sign Verity root hash with it
    openssl smime -sign -nocerts -noattr -binary -in "${image}.roothash" -inkey "${image}.key" -signer "${image}.crt" -outform der -out "${image}.roothash.p7s"
    # Generate signature partition JSON data
    echo '{"rootHash":"'"${roothash}"'","signature":"'"$(base64 -w 0 < "${image}.roothash.p7s")"'"}' > "${image}.verity-sig"
    # Pad it
    truncate -s "${signature_size}" "${image}.verity-sig"
    # Register certificate in the (userspace) verity key ring
    mkdir -p /run/verity.d
    ln -s "${image}.crt" /run/verity.d/ok.crt
fi

# Construct a UUID from hash
# input:  11111111222233334444555566667777
# output: 11111111-2222-3333-4444-555566667777
uuid="$(head -c 32 "${image}.roothash" | sed -r 's/(.{8})(.{4})(.{4})(.{4})(.+)/\1-\2-\3-\4-\5/')"
echo -e "label: gpt\nsize=${root_size}, type=${root_guid}, uuid=${uuid}" | sfdisk "${image}.gpt"
uuid="$(tail -c 32 "${image}.roothash" | sed -r 's/(.{8})(.{4})(.{4})(.{4})(.+)/\1-\2-\3-\4-\5/')"
echo -e "size=${verity_size}, type=${verity_guid}, uuid=${uuid}" | sfdisk "${image}.gpt" --append
if [ "${HAVE_OPENSSL}" -eq 1 ]; then
    echo -e "size=${signature_size}, type=${signature_guid}" | sfdisk "${image}.gpt" --append
fi
sfdisk --part-label "${image}.gpt" 1 "Root Partition"
sfdisk --part-label "${image}.gpt" 2 "Verity Partition"
if [ "${HAVE_OPENSSL}" -eq 1 ]; then
    sfdisk --part-label "${image}.gpt" 3 "Signature Partition"
fi
loop="$(losetup --show -P -f "${image}.gpt")"
dd if="${image}.raw" of="${loop}p1"
dd if="${image}.verity" of="${loop}p2"
if [ "${HAVE_OPENSSL}" -eq 1 ]; then
    dd if="${image}.verity-sig" of="${loop}p3"
fi
losetup -d "${loop}"

# Derive partition UUIDs from root hash, in UUID syntax
ROOT_UUID="$(systemd-id128 -u show "$(head -c 32 "${image}.roothash")" -u | tail -n 1 | cut -b 6-)"
VERITY_UUID="$(systemd-id128 -u show "$(tail -c 32 "${image}.roothash")" -u | tail -n 1 | cut -b 6-)"

systemd-dissect --json=short --root-hash "${roothash}" "${image}.gpt" | grep -q '{"rw":"ro","designator":"root","partition_uuid":"'"$ROOT_UUID"'","partition_label":"Root Partition","fstype":"squashfs","architecture":"'"$architecture"'","verity":"yes",'
systemd-dissect --json=short --root-hash "${roothash}" "${image}.gpt" | grep -q '{"rw":"ro","designator":"root-verity","partition_uuid":"'"$VERITY_UUID"'","partition_label":"Verity Partition","fstype":"DM_verity_hash","architecture":"'"$architecture"'","verity":null,'
systemd-dissect --root-hash "${roothash}" "${image}.gpt" | grep -q -F "MARKER=1"
systemd-dissect --root-hash "${roothash}" "${image}.gpt" | grep -q -F -f <(sed 's/"//g' "$os_release")

systemd-dissect --root-hash "${roothash}" --mount "${image}.gpt" "${image_dir}/mount"
grep -q -F -f "$os_release" "${image_dir}/mount/usr/lib/os-release"
grep -q -F -f "$os_release" "${image_dir}/mount/etc/os-release"
grep -q -F "MARKER=1" "${image_dir}/mount/usr/lib/os-release"
umount "${image_dir}/mount"

# add explicit -p MountAPIVFS=yes once to test the parser
systemd-run -P -p RootImage="${image}.gpt" -p RootHash="${roothash}" -p MountAPIVFS=yes cat /usr/lib/os-release | grep -q -F "MARKER=1"

systemd-run -P -p RootImage="${image}.raw" -p RootImageOptions="root:nosuid,dev home:ro,dev ro,noatime" mount | grep -F "squashfs" | grep -q -F "nosuid"
systemd-run -P -p RootImage="${image}.gpt" -p RootImageOptions="root:ro,noatime root:ro,dev" mount | grep -F "squashfs" | grep -q -F "noatime"

mkdir -p "${image_dir}/result"
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
grep -F "squashfs" "${image_dir}/result/a" | grep -q -F "noatime"
grep -F "squashfs" "${image_dir}/result/a" | grep -q -F -v "nosuid"

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
grep -F "squashfs" "${image_dir}/result/b" | grep -q -F "noatime"

# Check that specifier escape is applied %%foo → %foo
busctl get-property org.freedesktop.systemd1 /org/freedesktop/systemd1/unit/testservice_2d50b_2eservice org.freedesktop.systemd1.Service RootImageOptions | grep -F "nosuid,dev,%foo"

# Now do some checks with MountImages, both by itself, with options and in combination with RootImage, and as single FS or GPT image
systemd-run -P -p MountImages="${image}.gpt:/run/img1 ${image}.raw:/run/img2" cat /run/img1/usr/lib/os-release | grep -q -F "MARKER=1"
systemd-run -P -p MountImages="${image}.gpt:/run/img1 ${image}.raw:/run/img2" cat /run/img2/usr/lib/os-release | grep -q -F "MARKER=1"
systemd-run -P -p MountImages="${image}.gpt:/run/img1 ${image}.raw:/run/img2:nosuid,dev" mount | grep -F "squashfs" | grep -q -F "nosuid"
systemd-run -P -p MountImages="${image}.gpt:/run/img1:root:nosuid ${image}.raw:/run/img2:home:suid" mount | grep -F "squashfs" | grep -q -F "nosuid"
systemd-run -P -p MountImages="${image}.raw:/run/img2\:3" cat /run/img2:3/usr/lib/os-release | grep -q -F "MARKER=1"
systemd-run -P -p MountImages="${image}.raw:/run/img2\:3:nosuid" mount | grep -F "squashfs" | grep -q -F "nosuid"
systemd-run -P -p TemporaryFileSystem=/run -p RootImage="${image}.raw" -p MountImages="${image}.gpt:/run/img1 ${image}.raw:/run/img2" cat /usr/lib/os-release | grep -q -F "MARKER=1"
systemd-run -P -p TemporaryFileSystem=/run -p RootImage="${image}.raw" -p MountImages="${image}.gpt:/run/img1 ${image}.raw:/run/img2" cat /run/img1/usr/lib/os-release | grep -q -F "MARKER=1"
systemd-run -P -p TemporaryFileSystem=/run -p RootImage="${image}.gpt" -p RootHash="${roothash}" -p MountImages="${image}.gpt:/run/img1 ${image}.raw:/run/img2" cat /run/img2/usr/lib/os-release | grep -q -F "MARKER=1"
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
grep -q -F "MARKER=1" "${image_dir}/result/c"
grep -F "squashfs" "${image_dir}/result/c" | grep -q -F "noatime"
grep -F "squashfs" "${image_dir}/result/c" | grep -q -F -v "nosuid"

# Adding a new mounts at runtime works if the unit is in the active state,
# so use Type=notify to make sure there's no race condition in the test
cat >/run/systemd/system/testservice-50d.service <<EOF
[Service]
RuntimeMaxSec=300
Type=notify
RemainAfterExit=yes
MountAPIVFS=yes
PrivateTmp=yes
ExecStart=/bin/sh -c 'systemd-notify --ready; while ! grep -q -F MARKER /tmp/img/usr/lib/os-release; do sleep 0.1; done; mount | grep -F "/tmp/img" | grep -q -F "nosuid"'
EOF
systemctl start testservice-50d.service

systemctl mount-image --mkdir testservice-50d.service "${image}.raw" /tmp/img root:nosuid

while systemctl show -P SubState testservice-50d.service | grep -q running
do
    sleep 0.1
done

systemctl is-active testservice-50d.service

# ExtensionImages will set up an overlay
systemd-run -P --property ExtensionImages=/usr/share/app0.raw --property RootImage="${image}.raw" cat /opt/script0.sh | grep -q -F "extension-release.app0"
systemd-run -P --property ExtensionImages=/usr/share/app0.raw --property RootImage="${image}.raw" cat /usr/lib/systemd/system/some_file | grep -q -F "MARKER=1"
systemd-run -P --property ExtensionImages="/usr/share/app0.raw /usr/share/app1.raw" --property RootImage="${image}.raw" cat /opt/script0.sh | grep -q -F "extension-release.app0"
systemd-run -P --property ExtensionImages="/usr/share/app0.raw /usr/share/app1.raw" --property RootImage="${image}.raw" cat /usr/lib/systemd/system/some_file | grep -q -F "MARKER=1"
systemd-run -P --property ExtensionImages="/usr/share/app0.raw /usr/share/app1.raw" --property RootImage="${image}.raw" cat /opt/script1.sh | grep -q -F "extension-release.app2"
systemd-run -P --property ExtensionImages="/usr/share/app0.raw /usr/share/app1.raw" --property RootImage="${image}.raw" cat /usr/lib/systemd/system/other_file | grep -q -F "MARKER=1"
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

# ExtensionDirectories will set up an overlay
mkdir -p "${image_dir}/app0" "${image_dir}/app1"
systemd-run -P --property ExtensionDirectories="${image_dir}/nonexistant" --property RootImage="${image}.raw" cat /opt/script0.sh && { echo 'unexpected success'; exit 1; }
systemd-run -P --property ExtensionDirectories="${image_dir}/app0" --property RootImage="${image}.raw" cat /opt/script0.sh && { echo 'unexpected success'; exit 1; }
systemd-dissect --mount /usr/share/app0.raw "${image_dir}/app0"
systemd-dissect --mount /usr/share/app1.raw "${image_dir}/app1"
systemd-run -P --property ExtensionDirectories="${image_dir}/app0" --property RootImage="${image}.raw" cat /opt/script0.sh | grep -q -F "extension-release.app0"
systemd-run -P --property ExtensionDirectories="${image_dir}/app0" --property RootImage="${image}.raw" cat /usr/lib/systemd/system/some_file | grep -q -F "MARKER=1"
systemd-run -P --property ExtensionDirectories="${image_dir}/app0 ${image_dir}/app1" --property RootImage="${image}.raw" cat /opt/script0.sh | grep -q -F "extension-release.app0"
systemd-run -P --property ExtensionDirectories="${image_dir}/app0 ${image_dir}/app1" --property RootImage="${image}.raw" cat /usr/lib/systemd/system/some_file | grep -q -F "MARKER=1"
systemd-run -P --property ExtensionDirectories="${image_dir}/app0 ${image_dir}/app1" --property RootImage="${image}.raw" cat /opt/script1.sh | grep -q -F "extension-release.app2"
systemd-run -P --property ExtensionDirectories="${image_dir}/app0 ${image_dir}/app1" --property RootImage="${image}.raw" cat /usr/lib/systemd/system/other_file | grep -q -F "MARKER=1"
cat >/run/systemd/system/testservice-50f.service <<EOF
[Service]
MountAPIVFS=yes
TemporaryFileSystem=/run
RootImage=${image}.raw
ExtensionDirectories=${image_dir}/app0 ${image_dir}/app1
# Relevant only for sanitizer runs
UnsetEnvironment=LD_PRELOAD
ExecStart=/bin/bash -c '/opt/script0.sh | grep ID'
ExecStart=/bin/bash -c '/opt/script1.sh | grep ID'
Type=oneshot
RemainAfterExit=yes
EOF
systemctl start testservice-50f.service
systemctl is-active testservice-50f.service
umount "${image_dir}/app0"
umount "${image_dir}/app1"

echo OK >/testok

exit 0
