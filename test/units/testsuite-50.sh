#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
# shellcheck disable=SC2233,SC2235
set -eux
set -o pipefail

export SYSTEMD_LOG_LEVEL=debug

# shellcheck disable=SC2317
cleanup() {(
    set +ex

    if [ -z "${image_dir}" ]; then
        return
    fi
    umount "${image_dir}/app0"
    umount "${image_dir}/app1"
    umount "${image_dir}/app-nodistro"
    umount "${image_dir}/service-scoped-test"
    rm -rf "${image_dir}"
)}

udevadm control --log-level=debug

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

systemd-dissect --list "${image}.raw" | grep -q '^etc/os-release$'
systemd-dissect --mtree "${image}.raw" --mtree-hash yes | grep -qe "^./usr/bin/cat type=file mode=0755 uid=0 gid=0 size=[0-9]* sha256sum=[a-z0-9]*$"
systemd-dissect --mtree "${image}.raw" --mtree-hash no  | grep -qe "^./usr/bin/cat type=file mode=0755 uid=0 gid=0 size=[0-9]*$"

read -r SHA256SUM1 _ < <(systemd-dissect --copy-from "${image}.raw" etc/os-release | sha256sum)
test "$SHA256SUM1" != ""
read -r SHA256SUM2 _ < <(systemd-dissect --read-only --with "${image}.raw" sha256sum etc/os-release)
test "$SHA256SUM2" != ""
test "$SHA256SUM1" = "$SHA256SUM2"

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
systemd-dissect --umount "${image_dir}/mount"
systemd-dissect --umount "${image_dir}/mount2"

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

    # Create key pair
    openssl req -config "$OPENSSL_CONFIG" -new -x509 -newkey rsa:1024 -keyout "${image}.key" -out "${image}.crt" -days 365 -nodes
    # Sign Verity root hash with it
    openssl smime -sign -nocerts -noattr -binary -in "${image}.roothash" -inkey "${image}.key" -signer "${image}.crt" -outform der -out "${image}.roothash.p7s"
    # Generate signature partition JSON data
    echo '{"rootHash":"'"${roothash}"'","signature":"'"$(base64 -w 0 <"${image}.roothash.p7s")"'"}' >"${image}.verity-sig"
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
partitions=(
    "${loop:?}p1"
    "${loop:?}p2"
)
if [ "${HAVE_OPENSSL}" -eq 1 ]; then
    partitions+=( "${loop:?}p3" )
fi
# The kernel sometimes(?) does not emit "add" uevent for loop block partition devices.
# Let's not expect the devices to be initialized.
udevadm wait --timeout 60 --settle --initialized=no "${partitions[@]}"
udevadm lock --device="${loop}p1" dd if="${image}.raw" of="${loop}p1"
udevadm lock --device="${loop}p2" dd if="${image}.verity" of="${loop}p2"
if [ "${HAVE_OPENSSL}" -eq 1 ]; then
    udevadm lock --device="${loop}p3" dd if="${image}.verity-sig" of="${loop}p3"
fi
losetup -d "${loop}"

# Derive partition UUIDs from root hash, in UUID syntax
ROOT_UUID="$(systemd-id128 -u show "$(head -c 32 "${image}.roothash")" -u | tail -n 1 | cut -b 6-)"
VERITY_UUID="$(systemd-id128 -u show "$(tail -c 32 "${image}.roothash")" -u | tail -n 1 | cut -b 6-)"

systemd-dissect --json=short --root-hash "${roothash}" "${image}.gpt" | grep -q '{"rw":"ro","designator":"root","partition_uuid":"'"$ROOT_UUID"'","partition_label":"Root Partition","fstype":"squashfs","architecture":"'"$architecture"'","verity":"signed",'
systemd-dissect --json=short --root-hash "${roothash}" "${image}.gpt" | grep -q '{"rw":"ro","designator":"root-verity","partition_uuid":"'"$VERITY_UUID"'","partition_label":"Verity Partition","fstype":"DM_verity_hash","architecture":"'"$architecture"'","verity":null,'
if [ "${HAVE_OPENSSL}" -eq 1 ]; then
    systemd-dissect --json=short --root-hash "${roothash}" "${image}.gpt" | grep -q -E '{"rw":"ro","designator":"root-verity-sig","partition_uuid":"'".*"'","partition_label":"Signature Partition","fstype":"verity_hash_signature","architecture":"'"$architecture"'","verity":null,'
fi
systemd-dissect --root-hash "${roothash}" "${image}.gpt" | grep -q -F "MARKER=1"
systemd-dissect --root-hash "${roothash}" "${image}.gpt" | grep -q -F -f <(sed 's/"//g' "$os_release")

# Test image policies
systemd-dissect --validate "${image}.gpt"
systemd-dissect --validate "${image}.gpt" --image-policy='*'
(! systemd-dissect --validate "${image}.gpt" --image-policy='~')
(! systemd-dissect --validate "${image}.gpt" --image-policy='-')
(! systemd-dissect --validate "${image}.gpt" --image-policy=root=absent)
(! systemd-dissect --validate "${image}.gpt" --image-policy=swap=unprotected+encrypted+verity)
systemd-dissect --validate "${image}.gpt" --image-policy=root=unprotected
systemd-dissect --validate "${image}.gpt" --image-policy=root=verity
systemd-dissect --validate "${image}.gpt" --image-policy=root=verity:root-verity-sig=unused+absent
systemd-dissect --validate "${image}.gpt" --image-policy=root=verity:swap=absent
systemd-dissect --validate "${image}.gpt" --image-policy=root=verity:swap=absent+unprotected
(! systemd-dissect --validate "${image}.gpt" --image-policy=root=verity:root-verity=unused+absent)
systemd-dissect --validate "${image}.gpt" --image-policy=root=signed
(! systemd-dissect --validate "${image}.gpt" --image-policy=root=signed:root-verity-sig=unused+absent)
(! systemd-dissect --validate "${image}.gpt" --image-policy=root=signed:root-verity=unused+absent)

# Test RootImagePolicy= unit file setting
systemd-run --wait -P -p RootImage="${image}.gpt" -p RootHash="${roothash}" -p MountAPIVFS=yes cat /usr/lib/os-release | grep -q -F "MARKER=1"
systemd-run --wait -P -p RootImage="${image}.gpt" -p RootHash="${roothash}" -p RootImagePolicy='*' -p MountAPIVFS=yes cat /usr/lib/os-release | grep -q -F "MARKER=1"
(! systemd-run --wait -P -p RootImage="${image}.gpt" -p RootHash="${roothash}" -p RootImagePolicy='~' -p MountAPIVFS=yes cat /usr/lib/os-release | grep -q -F "MARKER=1")
(! systemd-run --wait -P -p RootImage="${image}.gpt" -p RootHash="${roothash}" -p RootImagePolicy='-' -p MountAPIVFS=yes cat /usr/lib/os-release | grep -q -F "MARKER=1")
(! systemd-run --wait -P -p RootImage="${image}.gpt" -p RootHash="${roothash}" -p RootImagePolicy='root=absent' -p MountAPIVFS=yes cat /usr/lib/os-release | grep -q -F "MARKER=1")
systemd-run --wait -P -p RootImage="${image}.gpt" -p RootHash="${roothash}" -p RootImagePolicy='root=verity' -p MountAPIVFS=yes cat /usr/lib/os-release | grep -q -F "MARKER=1"
systemd-run --wait -P -p RootImage="${image}.gpt" -p RootHash="${roothash}" -p RootImagePolicy='root=signed' -p MountAPIVFS=yes cat /usr/lib/os-release | grep -q -F "MARKER=1"
(! systemd-run --wait -P -p RootImage="${image}.gpt" -p RootHash="${roothash}" -p RootImagePolicy='root=encrypted' -p MountAPIVFS=yes cat /usr/lib/os-release | grep -q -F "MARKER=1")

systemd-dissect --root-hash "${roothash}" --mount "${image}.gpt" "${image_dir}/mount"
grep -q -F -f "$os_release" "${image_dir}/mount/usr/lib/os-release"
grep -q -F -f "$os_release" "${image_dir}/mount/etc/os-release"
grep -q -F "MARKER=1" "${image_dir}/mount/usr/lib/os-release"
systemd-dissect --umount "${image_dir}/mount"

systemd-dissect --root-hash "${roothash}" --mount "${image}.gpt" --in-memory "${image_dir}/mount"
grep -q -F -f "$os_release" "${image_dir}/mount/usr/lib/os-release"
grep -q -F -f "$os_release" "${image_dir}/mount/etc/os-release"
grep -q -F "MARKER=1" "${image_dir}/mount/usr/lib/os-release"
systemd-dissect --umount "${image_dir}/mount"

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
ExecStart=/bin/sh -c ' \\
    systemd-notify --ready; \\
    while [ ! -f /tmp/img/usr/lib/os-release ] || ! grep -q -F MARKER /tmp/img/usr/lib/os-release; do \\
        sleep 0.1; \\
    done; \\
    mount; \\
    mount | grep -F "on /tmp/img type squashfs" | grep -q -F "nosuid"; \\
'
EOF
systemctl start testservice-50d.service

# Mount twice to exercise mount-beneath (on kernel 6.5+, on older kernels it will just overmount)
mkdir -p /tmp/wrong/foo
mksquashfs /tmp/wrong/foo /tmp/wrong.raw
systemctl mount-image --mkdir testservice-50d.service /tmp/wrong.raw /tmp/img
test "$(systemctl show -P SubState testservice-50d.service)" = "running"
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
systemd-run -P --property ExtensionImages=/usr/share/app-nodistro.raw --property RootImage="${image}.raw" cat /usr/lib/systemd/system/some_file | grep -q -F "MARKER=1"
systemd-run -P --property ExtensionImages=/etc/service-scoped-test.raw --property RootImage="${image}.raw" cat /etc/systemd/system/some_file | grep -q -F "MARKER_CONFEXT_123"
# Check that using a symlink to NAME-VERSION.raw works as long as the symlink has the correct name NAME.raw
mkdir -p /usr/share/symlink-test/
cp /usr/share/app-nodistro.raw /usr/share/symlink-test/app-nodistro-v1.raw
ln -fs /usr/share/symlink-test/app-nodistro-v1.raw /usr/share/symlink-test/app-nodistro.raw
systemd-run -P --property ExtensionImages=/usr/share/symlink-test/app-nodistro.raw --property RootImage="${image}.raw" cat /usr/lib/systemd/system/some_file | grep -q -F "MARKER=1"

# Symlink check again but for confext
mkdir -p /etc/symlink-test/
cp /etc/service-scoped-test.raw /etc/symlink-test/service-scoped-test-v1.raw
ln -fs /etc/symlink-test/service-scoped-test-v1.raw /etc/symlink-test/service-scoped-test.raw
systemd-run -P --property ExtensionImages=/etc/symlink-test/service-scoped-test.raw --property RootImage="${image}.raw" cat /etc/systemd/system/some_file | grep -q -F "MARKER_CONFEXT_123"
# And again mixing sysext and confext
systemd-run -P \
    --property ExtensionImages=/usr/share/symlink-test/app-nodistro.raw \
    --property ExtensionImages=/etc/symlink-test/service-scoped-test.raw \
    --property RootImage="${image}.raw" cat /etc/systemd/system/some_file | grep -q -F "MARKER_CONFEXT_123"
systemd-run -P \
    --property ExtensionImages=/usr/share/symlink-test/app-nodistro.raw \
    --property ExtensionImages=/etc/symlink-test/service-scoped-test.raw \
    --property RootImage="${image}.raw" cat /usr/lib/systemd/system/some_file | grep -q -F "MARKER=1"

cat >/run/systemd/system/testservice-50e.service <<EOF
[Service]
MountAPIVFS=yes
TemporaryFileSystem=/run /var/lib
StateDirectory=app0
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
mkdir -p "${image_dir}/app0" "${image_dir}/app1" "${image_dir}/app-nodistro" "${image_dir}/service-scoped-test"
(! systemd-run -P --property ExtensionDirectories="${image_dir}/nonexistent" --property RootImage="${image}.raw" cat /opt/script0.sh)
(! systemd-run -P --property ExtensionDirectories="${image_dir}/app0" --property RootImage="${image}.raw" cat /opt/script0.sh)
systemd-dissect --mount /usr/share/app0.raw "${image_dir}/app0"
systemd-dissect --mount /usr/share/app1.raw "${image_dir}/app1"
systemd-dissect --mount /usr/share/app-nodistro.raw "${image_dir}/app-nodistro"
systemd-dissect --mount /etc/service-scoped-test.raw "${image_dir}/service-scoped-test"
systemd-run -P --property ExtensionDirectories="${image_dir}/app0" --property RootImage="${image}.raw" cat /opt/script0.sh | grep -q -F "extension-release.app0"
systemd-run -P --property ExtensionDirectories="${image_dir}/app0" --property RootImage="${image}.raw" cat /usr/lib/systemd/system/some_file | grep -q -F "MARKER=1"
systemd-run -P --property ExtensionDirectories="${image_dir}/app0 ${image_dir}/app1" --property RootImage="${image}.raw" cat /opt/script0.sh | grep -q -F "extension-release.app0"
systemd-run -P --property ExtensionDirectories="${image_dir}/app0 ${image_dir}/app1" --property RootImage="${image}.raw" cat /usr/lib/systemd/system/some_file | grep -q -F "MARKER=1"
systemd-run -P --property ExtensionDirectories="${image_dir}/app0 ${image_dir}/app1" --property RootImage="${image}.raw" cat /opt/script1.sh | grep -q -F "extension-release.app2"
systemd-run -P --property ExtensionDirectories="${image_dir}/app0 ${image_dir}/app1" --property RootImage="${image}.raw" cat /usr/lib/systemd/system/other_file | grep -q -F "MARKER=1"
systemd-run -P --property ExtensionDirectories="${image_dir}/app-nodistro" --property RootImage="${image}.raw" cat /usr/lib/systemd/system/some_file | grep -q -F "MARKER=1"
systemd-run -P --property ExtensionDirectories="${image_dir}/service-scoped-test" --property RootImage="${image}.raw" cat /etc/systemd/system/some_file | grep -q -F "MARKER_CONFEXT_123"
cat >/run/systemd/system/testservice-50f.service <<EOF
[Service]
MountAPIVFS=yes
TemporaryFileSystem=/run /var/lib
StateDirectory=app0
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
systemd-dissect --umount "${image_dir}/app0"
systemd-dissect --umount "${image_dir}/app1"

# Test that an extension consisting of an empty directory under /etc/extensions/ takes precedence
mkdir -p /var/lib/extensions/
ln -s /usr/share/app-nodistro.raw /var/lib/extensions/app-nodistro.raw
systemd-sysext merge
grep -q -F "MARKER=1" /usr/lib/systemd/system/some_file
systemd-sysext unmerge
mkdir -p /etc/extensions/app-nodistro
systemd-sysext merge
test ! -e /usr/lib/systemd/system/some_file
systemd-sysext unmerge
rmdir /etc/extensions/app-nodistro

# Similar, but go via varlink
varlinkctl call /run/systemd/io.systemd.sysext io.systemd.sysext.List '{}'
(! grep -q -F "MARKER=1" /usr/lib/systemd/system/some_file )
varlinkctl call /run/systemd/io.systemd.sysext io.systemd.sysext.Merge '{}'
grep -q -F "MARKER=1" /usr/lib/systemd/system/some_file
varlinkctl call /run/systemd/io.systemd.sysext io.systemd.sysext.Refresh '{}'
grep -q -F "MARKER=1" /usr/lib/systemd/system/some_file
varlinkctl call /run/systemd/io.systemd.sysext io.systemd.sysext.Unmerge '{}'
(! grep -q -F "MARKER=1" /usr/lib/systemd/system/some_file )

# Check that extensions cannot contain os-release
mkdir -p /run/extensions/app-reject/usr/lib/{extension-release.d/,systemd/system}
echo "ID=_any" >/run/extensions/app-reject/usr/lib/extension-release.d/extension-release.app-reject
echo "ID=_any" >/run/extensions/app-reject/usr/lib/os-release
touch /run/extensions/app-reject/usr/lib/systemd/system/other_file
(! systemd-sysext merge)
test ! -e /usr/lib/systemd/system/some_file
test ! -e /usr/lib/systemd/system/other_file
systemd-sysext unmerge
rm -rf /run/extensions/app-reject
rm /var/lib/extensions/app-nodistro.raw

# Some super basic test that RootImage= works with .v/ dirs
VBASE="vtest$RANDOM"
VDIR="/tmp/${VBASE}.v"
mkdir "$VDIR"

ln -s ${image}.raw "$VDIR/${VBASE}_33.raw"
ln -s ${image}.raw "$VDIR/${VBASE}_34.raw"
ln -s ${image}.raw "$VDIR/${VBASE}_35.raw"

systemd-run -P -p RootImage="$VDIR" cat /usr/lib/os-release | grep -q -F "MARKER=1"

rm "$VDIR/${VBASE}_33.raw" "$VDIR/${VBASE}_34.raw" "$VDIR/${VBASE}_35.raw"
rmdir "$VDIR"

mkdir -p /run/machines /run/portables /run/extensions
touch /run/machines/a.raw /run/portables/b.raw /run/extensions/c.raw

systemd-dissect --discover --json=short >/tmp/discover.json
grep -q -F '{"name":"a","type":"raw","class":"machine","ro":false,"path":"/run/machines/a.raw"' /tmp/discover.json
grep -q -F '{"name":"b","type":"raw","class":"portable","ro":false,"path":"/run/portables/b.raw"' /tmp/discover.json
grep -q -F '{"name":"c","type":"raw","class":"sysext","ro":false,"path":"/run/extensions/c.raw"' /tmp/discover.json
rm /tmp/discover.json /run/machines/a.raw /run/portables/b.raw /run/extensions/c.raw

# Check that the /sbin/mount.ddi helper works
T="/tmp/mounthelper.$RANDOM"
mount -t ddi "${image}.gpt" "$T" -o ro,X-mount.mkdir,discard
umount -R "$T"
rmdir "$T"

LOOP="$(systemd-dissect --attach --loop-ref=waldo "${image}.raw")"

# Wait until the symlinks we want to test are established
udevadm trigger -w "$LOOP"

# Check if the /dev/loop/* symlinks really reference the right device
test /dev/disk/by-loop-ref/waldo -ef "$LOOP"

if [ "$(stat -c '%Hd:%Ld' "${image}.raw")" != '?d:?d' ] ; then
   # Old stat didn't know the %Hd and %Ld specifiers and turned them into ?d
   # instead. Let's simply skip the test on such old systems.
   test "$(stat -c '/dev/disk/by-loop-inode/%Hd:%Ld-%i' "${image}.raw")" -ef "$LOOP"
fi

# Detach by loopback device
systemd-dissect --detach "$LOOP"

# Test long reference name.
# Note, sizeof_field(struct loop_info64, lo_file_name) == 64,
# and --loop-ref accepts upto 63 characters, and udev creates symlink
# based on the name when it has upto _62_ characters.
name="$(for _ in {1..62}; do echo -n 'x'; done)"
LOOP="$(systemd-dissect --attach --loop-ref="$name" "${image}.raw")"
udevadm trigger -w "$LOOP"

# Check if the /dev/disk/by-loop-ref/$name symlink really references the right device
test "/dev/disk/by-loop-ref/$name" -ef "$LOOP"

# Detach by the /dev/disk/by-loop-ref symlink
systemd-dissect --detach "/dev/disk/by-loop-ref/$name"

name="$(for _ in {1..63}; do echo -n 'x'; done)"
LOOP="$(systemd-dissect --attach --loop-ref="$name" "${image}.raw")"
udevadm trigger -w "$LOOP"

# Check if the /dev/disk/by-loop-ref/$name symlink does not exist
test ! -e "/dev/disk/by-loop-ref/$name"

# Detach by backing inode
systemd-dissect --detach "${image}.raw"
(! systemd-dissect --detach "${image}.raw")

# check for confext functionality
mkdir -p /run/confexts/test/etc/extension-release.d
echo "ID=_any" >/run/confexts/test/etc/extension-release.d/extension-release.test
echo "ARCHITECTURE=_any" >>/run/confexts/test/etc/extension-release.d/extension-release.test
echo "MARKER_CONFEXT_123" >/run/confexts/test/etc/testfile
cat <<EOF >/run/confexts/test/etc/testscript
#!/bin/bash
echo "This should not happen"
EOF
chmod +x /run/confexts/test/etc/testscript
systemd-confext merge
grep -q -F "MARKER_CONFEXT_123" /etc/testfile
(! /etc/testscript)
systemd-confext status
systemd-confext unmerge
rm -rf /run/confexts/

unsquashfs -no-xattrs -d /tmp/img "${image}.raw"
systemd-run --unit=test-root-ephemeral \
    -p RootDirectory=/tmp/img \
    -p RootEphemeral=yes \
    -p Type=exec \
    bash -c "touch /abc && sleep infinity"
test -n "$(ls -A /var/lib/systemd/ephemeral-trees)"
systemctl stop test-root-ephemeral
# shellcheck disable=SC2016
timeout 10 bash -c 'until test -z "$(ls -A /var/lib/systemd/ephemeral-trees)"; do sleep .5; done'
test ! -f /tmp/img/abc

systemd-dissect --mtree /tmp/img
systemd-dissect --list /tmp/img

read -r SHA256SUM1 _ < <(systemd-dissect --copy-from /tmp/img etc/os-release | sha256sum)
test "$SHA256SUM1" != ""

echo abc > abc
systemd-dissect --copy-to /tmp/img abc /abc
test -f /tmp/img/abc

# Test for dissect tool support with systemd-sysext
mkdir -p /run/extensions/ testkit/usr/lib/extension-release.d/
echo "ID=_any" >testkit/usr/lib/extension-release.d/extension-release.testkit
echo "ARCHITECTURE=_any" >>testkit/usr/lib/extension-release.d/extension-release.testkit
echo "MARKER_SYSEXT_123" >testkit/usr/lib/testfile
mksquashfs testkit/ testkit.raw
cp testkit.raw /run/extensions/
unsquashfs -l /run/extensions/testkit.raw
systemd-dissect --no-pager /run/extensions/testkit.raw | grep -q '✓ sysext for portable service'
systemd-dissect --no-pager /run/extensions/testkit.raw | grep -q '✓ sysext for system'
systemd-sysext merge
systemd-sysext status
grep -q -F "MARKER_SYSEXT_123" /usr/lib/testfile
systemd-sysext unmerge
rm -rf /run/extensions/ testkit/

# Test for dissect tool support with systemd-confext
mkdir -p /run/confexts/ testjob/etc/extension-release.d/
echo "ID=_any" >testjob/etc/extension-release.d/extension-release.testjob
echo "ARCHITECTURE=_any" >>testjob/etc/extension-release.d/extension-release.testjob
echo "MARKER_CONFEXT_123" >testjob/etc/testfile
mksquashfs testjob/ testjob.raw
cp testjob.raw /run/confexts/
unsquashfs -l /run/confexts/testjob.raw
systemd-dissect --no-pager /run/confexts/testjob.raw | grep -q '✓ confext for system'
systemd-dissect --no-pager /run/confexts/testjob.raw | grep -q '✓ confext for portable service'
systemd-confext merge
systemd-confext status
grep -q -F "MARKER_CONFEXT_123" /etc/testfile
systemd-confext unmerge
rm -rf /run/confexts/ testjob/

systemd-run -P -p RootImage="${image}.raw" cat /run/host/os-release | cmp "${os_release}"

# Test that systemd-sysext reloads the daemon.
mkdir -p /var/lib/extensions/
ln -s /usr/share/app-reload.raw /var/lib/extensions/app-reload.raw
systemd-sysext merge --no-reload
# the service should not be running
if systemctl --quiet is-active foo.service; then
    echo "foo.service should not be active"
    exit 1
fi
systemd-sysext unmerge --no-reload
systemd-sysext merge
for RETRY in $(seq 60) LAST; do
  if journalctl --boot --unit foo.service | grep -q -P 'echo\[[0-9]+\]: foo'; then
    break
  fi
  if [ "${RETRY}" = LAST ]; then
    echo "Output of foo.service not found"
    exit 1
  fi
  sleep 0.5
done
systemd-sysext unmerge --no-reload
# Grep on the Warning to find the warning helper mentioning the daemon reload.
systemctl status foo.service 2>&1 | grep -q -F "Warning"
systemd-sysext merge
systemd-sysext unmerge
systemctl status foo.service 2>&1 | grep -v -q -F "Warning"
rm /var/lib/extensions/app-reload.raw

# Test systemd-repart --make-ddi=:
if command -v mksquashfs >/dev/null 2>&1; then

    openssl req -config "$OPENSSL_CONFIG" -subj="/CN=waldo" -x509 -sha256 -nodes -days 365 -newkey rsa:4096 -keyout /tmp/test-50-privkey.key -out /tmp/test-50-cert.crt

    mkdir -p /tmp/test-50-confext/etc/extension-release.d/

    echo "foobar50" > /tmp/test-50-confext/etc/waldo

    ( grep -e '^\(ID\|VERSION_ID\)=' /etc/os-release ; echo IMAGE_ID=waldo ; echo IMAGE_VERSION=7 ) > /tmp/test-50-confext/etc/extension-release.d/extension-release.waldo

    mkdir -p /run/confexts

    SYSTEMD_REPART_OVERRIDE_FSTYPE=squashfs systemd-repart -C -s /tmp/test-50-confext --certificate=/tmp/test-50-cert.crt --private-key=/tmp/test-50-privkey.key /run/confexts/waldo.confext.raw
    rm -rf /tmp/test-50-confext

    mkdir -p /run/verity.d
    cp /tmp/test-50-cert.crt /run/verity.d/
    systemd-dissect --mtree /run/confexts/waldo.confext.raw

    systemd-confext refresh

    read -r X < /etc/waldo
    test "$X" = foobar50

    rm /run/confexts/waldo.confext.raw

    systemd-confext refresh

    (! test -f /etc/waldo )

    mkdir -p /tmp/test-50-sysext/usr/lib/extension-release.d/

    # Make sure the sysext is big enough to not fit in the minimum partition size of repart so we know the
    # Minimize= logic is working.
    truncate --size=50M /tmp/test-50-sysext/usr/waldo

    ( grep -e '^\(ID\|VERSION_ID\)=' /etc/os-release ; echo IMAGE_ID=waldo ; echo IMAGE_VERSION=7 ) > /tmp/test-50-sysext/usr/lib/extension-release.d/extension-release.waldo

    mkdir -p /run/extensions

    SYSTEMD_REPART_OVERRIDE_FSTYPE=squashfs systemd-repart -S -s /tmp/test-50-sysext --certificate=/tmp/test-50-cert.crt --private-key=/tmp/test-50-privkey.key /run/extensions/waldo.sysext.raw

    systemd-dissect --mtree /run/extensions/waldo.sysext.raw

    systemd-sysext refresh

    test -f /usr/waldo

    rm /run/verity.d/test-50-cert.crt /run/extensions/waldo.sysext.raw /tmp/test-50-cert.crt /tmp/test-50-privkey.key

    systemd-sysext refresh

    (! test -f /usr/waldo)
fi

# Sneak in a couple of expected-to-fail invocations to cover
# https://github.com/systemd/systemd/issues/29610
(! systemd-run -P -p MountImages="/this/should/definitely/not/exist.img:/run/img2\:3:nosuid" false)
(! systemd-run -P -p ExtensionImages="/this/should/definitely/not/exist.img" false)
(! systemd-run -P -p RootImage="/this/should/definitely/not/exist.img" false)
(! systemd-run -P -p ExtensionDirectories="/foo/bar /foo/baz" false)

touch /testok
