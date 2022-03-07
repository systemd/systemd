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

portablectl "${ARGS[@]}" attach --now --runtime /usr/share/minimal_0.raw minimal-app0

systemctl is-active minimal-app0.service
systemctl is-active minimal-app0-foo.service
systemctl is-active minimal-app0-bar.service && exit 1

portablectl "${ARGS[@]}" reattach --now --runtime /usr/share/minimal_1.raw minimal-app0

systemctl is-active minimal-app0.service
systemctl is-active minimal-app0-bar.service
systemctl is-active minimal-app0-foo.service && exit 1

portablectl list | grep -q -F "minimal_1"

portablectl detach --now --runtime /usr/share/minimal_1.raw minimal-app0

portablectl list | grep -q -F "No images."

# portablectl also works with directory paths rather than images

unsquashfs -dest /tmp/minimal_0 /usr/share/minimal_0.raw
unsquashfs -dest /tmp/minimal_1 /usr/share/minimal_1.raw

portablectl "${ARGS[@]}" attach --copy=symlink --now --runtime /tmp/minimal_0 minimal-app0

systemctl is-active minimal-app0.service
systemctl is-active minimal-app0-foo.service
systemctl is-active minimal-app0-bar.service && exit 1

portablectl "${ARGS[@]}" reattach --now --enable --runtime /tmp/minimal_1 minimal-app0

systemctl is-active minimal-app0.service
systemctl is-active minimal-app0-bar.service
systemctl is-active minimal-app0-foo.service && exit 1

portablectl list | grep -q -F "minimal_1"

portablectl detach --now --enable --runtime /tmp/minimal_1 minimal-app0

portablectl list | grep -q -F "No images."

root="/usr/share/minimal_0.raw"
app1="/usr/share/app1.raw"

portablectl "${ARGS[@]}"  attach --now --runtime --extension ${app1} ${root} app1

systemctl is-active app1.service

portablectl "${ARGS[@]}"  reattach --now --runtime --extension ${app1} ${root} app1

systemctl is-active app1.service
portablectl inspect --cat --extension ${app1} ${root} app1 | grep -F "MARKER=1"
portablectl inspect --cat --extension ${app1} ${root} app1 | grep -F "Extension Release: /usr/share/app1.raw"
portablectl inspect --cat --extension ${app1} ${root} app1 | grep -F "ExecStart=/opt/script1.sh"

portablectl detach --now --runtime --extension ${app1} ${root} app1

# portablectl also works with directory paths rather than images

mkdir /tmp/rootdir /tmp/app1 /tmp/overlay
mount ${app1} /tmp/app1
mount ${root} /tmp/rootdir
mount -t overlay overlay -o lowerdir=/tmp/app1:/tmp/rootdir /tmp/overlay

portablectl "${ARGS[@]}" attach --copy=symlink --now --runtime /tmp/overlay app1

systemctl is-active app1.service

portablectl detach --now --runtime overlay app1

umount /tmp/overlay
umount /tmp/rootdir
umount /tmp/app1

echo OK >/testok

exit 0
