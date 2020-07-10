#!/usr/bin/env bash
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
set -ex
set -o pipefail

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

image="${image_dir}/img"
mkdir -p ${image}/usr/lib ${image}/etc
cp /usr/lib/os-release ${image}/usr/lib/
cp /etc/machine-id /etc/os-release ${image}/etc/
mksquashfs ${image} ${image}.raw
veritysetup format ${image}.raw ${image}.verity | grep '^Root hash:' | cut -f2 | tr -d '\n' > ${image}.roothash
roothash="$(cat ${image}.roothash)"

/usr/lib/systemd/systemd-dissect ${image}.raw | grep -q -F "Found read-only 'root' partition of type squashfs with verity"
/usr/lib/systemd/systemd-dissect ${image}.raw | grep -q -F -f /usr/lib/os-release

mv ${image}.verity ${image}.fooverity
mv ${image}.roothash ${image}.foohash
/usr/lib/systemd/systemd-dissect ${image}.raw --root-hash=${roothash} --verity-data=${image}.fooverity | grep -q -F "Found read-only 'root' partition of type squashfs with verity"
/usr/lib/systemd/systemd-dissect ${image}.raw --root-hash=${roothash} --verity-data=${image}.fooverity | grep -q -F -f /usr/lib/os-release
mv ${image}.fooverity ${image}.verity
mv ${image}.foohash ${image}.roothash

mkdir -p ${image_dir}/mount
/usr/lib/systemd/systemd-dissect --mount ${image}.raw ${image_dir}/mount
pushd ${image_dir}/mount/etc/
(cd /etc; md5sum os-release) | md5sum -c
cd ../usr/lib
(cd /usr/lib; md5sum os-release) | md5sum -c
popd
umount ${image_dir}/mount

echo OK > /testok

exit 0
