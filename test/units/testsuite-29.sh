#!/usr/bin/env bash
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
set -eux
set -o pipefail

ARGS=()
if [[ -v ASAN_OPTIONS || -v UBSAN_OPTIONS ]]; then
    # If we're running under sanitizers, we need to use a less restrictive
    # profile, otherwise LSan syscall would get blocked by seccomp
    ARGS+=(--profile=trusted)
fi

export SYSTEMD_LOG_LEVEL=debug
mkdir -p /run/systemd/system/systemd-portabled.service.d/
cat <<EOF >/run/systemd/system/systemd-portabled.service.d/override.conf
[Service]
Environment=SYSTEMD_LOG_LEVEL=debug
EOF

portablectl "${ARGS[@]}" attach --now --runtime /usr/share/minimal_0.raw app0

systemctl is-active app0.service
systemctl is-active app0-foo.service
set +o pipefail
set +e
systemctl is-active app0-bar.service && exit 1
set -e
set -o pipefail

portablectl "${ARGS[@]}" reattach --now --runtime /usr/share/minimal_1.raw app0

systemctl is-active app0.service
systemctl is-active app0-bar.service
set +o pipefail
set +e
systemctl is-active app0-foo.service && exit 1
set -e
set -o pipefail

portablectl list | grep -q -F "minimal_1"

portablectl detach --now --runtime /usr/share/minimal_1.raw app0

portablectl list | grep -q -F "No images."

# portablectl also works with directory paths rather than images

unsquashfs -dest /tmp/minimal_0 /usr/share/minimal_0.raw
unsquashfs -dest /tmp/minimal_1 /usr/share/minimal_1.raw

portablectl "${ARGS[@]}" attach --copy=symlink --now --runtime /tmp/minimal_0 app0

systemctl is-active app0.service
systemctl is-active app0-foo.service
set +o pipefail
set +e
systemctl is-active app0-bar.service && exit 1
set -e
set -o pipefail

portablectl "${ARGS[@]}" reattach --now --enable --runtime /tmp/minimal_1 app0

systemctl is-active app0.service
systemctl is-active app0-bar.service
set +o pipefail
set +e
systemctl is-active app0-foo.service && exit 1
set -e
set -o pipefail

portablectl list | grep -q -F "minimal_1"

portablectl detach --now --enable --runtime /tmp/minimal_1 app0

portablectl list | grep -q -F "No images."

portablectl "${ARGS[@]}" attach --now --runtime --extension /usr/share/app0.raw /usr/share/minimal_0.raw app0

systemctl is-active app0.service

portablectl "${ARGS[@]}" reattach --now --runtime --extension /usr/share/app0.raw /usr/share/minimal_1.raw app0

systemctl is-active app0.service

portablectl detach --now --runtime --extension /usr/share/app0.raw /usr/share/minimal_1.raw app0

portablectl "${ARGS[@]}" attach --now --runtime --extension /usr/share/app1.raw /usr/share/minimal_0.raw app1

systemctl is-active app1.service

portablectl "${ARGS[@]}" reattach --now --runtime --extension /usr/share/app1.raw /usr/share/minimal_1.raw app1

systemctl is-active app1.service

portablectl detach --now --runtime --extension /usr/share/app1.raw /usr/share/minimal_1.raw app1

# portablectl also works with directory paths rather than images

mkdir /tmp/rootdir /tmp/app1 /tmp/overlay
mount /usr/share/app1.raw /tmp/app1
mount /usr/share/minimal_0.raw /tmp/rootdir
mount -t overlay overlay -o lowerdir=/tmp/app1:/tmp/rootdir /tmp/overlay

portablectl "${ARGS[@]}" attach --copy=symlink --now --runtime /tmp/overlay app1

systemctl is-active app1.service

portablectl detach --now --runtime overlay app1

umount /tmp/overlay
umount /tmp/rootdir
umount /tmp/app1

echo OK >/testok

exit 0
