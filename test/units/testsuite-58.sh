#!/usr/bin/env bash
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
set -ex
set -o pipefail

export SYSTEMD_LOG_LEVEL=debug

cp /usr/share/minimal.raw /tmp/minimal_0.raw
unsquashfs -dest /tmp/minimal_0 /tmp/minimal_0.raw
cp -r /tmp/minimal_0 /tmp/minimal_1
sed -i "s/MARKER=1/MARKER=2/g" /tmp/minimal_0/usr/lib/os-release
mksquashfs /tmp/minimal_1 /tmp/minimal_1.raw

portablectl attach --now --runtime /tmp/minimal_0.raw app0

systemctl is-active app0.service

portablectl reattach --now --runtime /tmp/minimal_1.raw app0

systemctl is-active app0.service

portablectl list | grep -q -F "minimal_1"

portablectl detach --now --runtime /tmp/minimal_1.raw app0

portablectl list | grep -q -F "No images."

# portablectl also works with directory paths rather than images

# some units might come and go, simulate that and ensure the right thing happens

cp /tmp/minimal_0/usr/lib/systemd/system/app0.service /tmp/minimal_0/usr/lib/systemd/system/app0-foo.service
cp /tmp/minimal_1/usr/lib/systemd/system/app0.service /tmp/minimal_1/usr/lib/systemd/system/app0-bar.service

portablectl attach --copy=symlink --now --runtime /tmp/minimal_0 app0

systemctl is-active app0.service
systemctl is-active app0-foo.service
set +o pipefail
set +e
systemctl is-active app0-bar.service && exit 1
set -e
set -o pipefail

portablectl reattach --now --runtime /tmp/minimal_1 app0

systemctl is-active app0.service
systemctl is-active app0-bar.service
set +o pipefail
set +e
systemctl is-active app0-foo.service && exit 1
set -e
set -o pipefail

portablectl list | grep -q -F "minimal_1"

portablectl detach --now --runtime /tmp/minimal_1 app0

portablectl list | grep -q -F "No images."

echo OK > /testok

exit 0
