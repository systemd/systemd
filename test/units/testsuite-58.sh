#!/usr/bin/env bash
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
set -ex
set -o pipefail

cd /tmp
cp /usr/share/minimal.raw minimal_0.raw
unsquashfs minimal_0.raw
sed -i "s/MARKER=1/MARKER=2/g" squashfs-root/usr/lib/os-release
mksquashfs squashfs-root minimal_1.raw

portablectl attach --now --runtime /tmp/minimal_0.raw app0

systemctl is-active app0.service

portablectl upgrade --now --runtime /tmp/minimal_1.raw app0

systemctl is-active app0.service

portablectl detach --now --runtime /tmp/minimal_1.raw app0

portablectl list | grep -q -F "No images."

# portablectl also works with directory paths rather than images

mkdir minimal_0 minimal_1
mount minimal_0.raw /tmp/minimal_0
mount minimal_1.raw /tmp/minimal_1

portablectl attach --copy=symlink --now --runtime /tmp/minimal_0 app0

systemctl is-active app0.service

portablectl upgrade --now --runtime /tmp/minimal_1 app0

systemctl is-active app0.service

portablectl detach --now --runtime /tmp/minimal_1 app0

portablectl list | grep -q -F "No images."

umount /tmp/minimal_0
umount /tmp/minimal_1

echo OK > /testok

exit 0
