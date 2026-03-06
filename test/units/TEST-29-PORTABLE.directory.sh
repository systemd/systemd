#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
# shellcheck disable=SC2233,SC2235
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# Arrays cannot be exported, so redefine in each test script
ARGS=()
if [[ -v ASAN_OPTIONS || -v UBSAN_OPTIONS ]]; then
    # If we're running under sanitizers, we need to use a less restrictive
    # profile, otherwise LSan syscall would get blocked by seccomp
    ARGS+=(--profile=trusted)
fi

unsquashfs -force -no-xattrs -d /tmp/minimal_0 /usr/share/minimal_0.raw
unsquashfs -force -no-xattrs -d /tmp/minimal_1 /usr/share/minimal_1.raw

portablectl "${ARGS[@]}" attach --copy=symlink --now --runtime /tmp/minimal_0 minimal-app0

systemctl is-active minimal-app0.service
systemctl is-active minimal-app0-foo.service
systemctl is-active minimal-app0-bar.service && exit 1

portablectl "${ARGS[@]}" reattach --now --enable --runtime /tmp/minimal_1 minimal-app0

systemctl is-active minimal-app0.service
systemctl is-active minimal-app0-bar.service
systemctl is-active minimal-app0-foo.service && exit 1

portablectl list | grep -F "minimal_1" >/dev/null
busctl tree org.freedesktop.portable1 --no-pager | grep -F '/org/freedesktop/portable1/image/minimal_5f1' >/dev/null

portablectl detach --now --enable --runtime /tmp/minimal_1 minimal-app0

portablectl list | grep -F "No images." >/dev/null
busctl tree org.freedesktop.portable1 --no-pager | grep -F '/org/freedesktop/portable1/image/minimal_5f1' && exit 1 >/dev/null

mkdir /tmp/rootdir /tmp/app0 /tmp/app1 /tmp/overlay /tmp/os-release-fix /tmp/os-release-fix/etc
mount /tmp/app0.raw /tmp/app0
mount /tmp/app1.raw /tmp/app1
mount /usr/share/minimal_0.raw /tmp/rootdir

# Fix up os-release to drop the valid PORTABLE_SERVICES field (because we are
# bypassing the sysext logic in portabled here it will otherwise not see the
# extensions additional valid prefix)
grep -v "^PORTABLE_PREFIXES=" /tmp/rootdir/etc/os-release >/tmp/os-release-fix/etc/os-release

mount -t overlay overlay -o lowerdir=/tmp/os-release-fix:/tmp/app1:/tmp/rootdir /tmp/overlay

grep . /tmp/overlay/usr/lib/extension-release.d/*
grep . /tmp/overlay/etc/os-release

portablectl "${ARGS[@]}" attach --copy=symlink --now --runtime /tmp/overlay app1

systemctl is-active app1.service

portablectl detach --now --runtime overlay app1

# Ensure --force works also when symlinking
mkdir -p /run/systemd/system.attached/app1.service.d
cat <<EOF >/run/systemd/system.attached/app1.service
[Unit]
Description=App 1
EOF
cat <<EOF >/run/systemd/system.attached/app1.service.d/10-profile.conf
[Unit]
Description=App 1
EOF
cat <<EOF >/run/systemd/system.attached/app1.service.d/20-portable.conf
[Unit]
Description=App 1
EOF
systemctl daemon-reload

portablectl "${ARGS[@]}" attach --force --copy=symlink --now --runtime /tmp/overlay app1

systemctl is-active app1.service

portablectl detach --now --runtime overlay app1

umount /tmp/overlay

portablectl "${ARGS[@]}" attach --copy=symlink --now --runtime --extension /tmp/app0 --extension /tmp/app1 /tmp/rootdir app0 app1

systemctl is-active app0.service
systemctl is-active app1.service

portablectl inspect --cat --extension app0 --extension app1 rootdir app0 app1 | grep -f /tmp/rootdir/usr/lib/os-release >/dev/null
portablectl inspect --cat --extension app0 --extension app1 rootdir app0 app1 | grep -f /tmp/app0/usr/lib/extension-release.d/extension-release.app0 >/dev/null
portablectl inspect --cat --extension app0 --extension app1 rootdir app0 app1 | grep -f /tmp/app1/usr/lib/extension-release.d/extension-release.app2 >/dev/null
portablectl inspect --cat --extension app0 --extension app1 rootdir app0 app1 | grep -f /tmp/app1/usr/lib/systemd/system/app1.service >/dev/null
portablectl inspect --cat --extension app0 --extension app1 rootdir app0 app1 | grep -f /tmp/app0/usr/lib/systemd/system/app0.service >/dev/null

grep -q -F "LogExtraFields=PORTABLE=app0" /run/systemd/system.attached/app0.service.d/20-portable.conf
grep -q -F "LogExtraFields=PORTABLE_ROOT=rootdir" /run/systemd/system.attached/app0.service.d/20-portable.conf
grep -q -F "LogExtraFields=PORTABLE_EXTENSION=app0" /run/systemd/system.attached/app0.service.d/20-portable.conf
grep -q -F "LogExtraFields=PORTABLE_EXTENSION_NAME_AND_VERSION=app" /run/systemd/system.attached/app0.service.d/20-portable.conf
grep -q -F "LogExtraFields=PORTABLE_EXTENSION=app1" /run/systemd/system.attached/app0.service.d/20-portable.conf
grep -q -F "LogExtraFields=PORTABLE_EXTENSION_NAME_AND_VERSION=app_1" /run/systemd/system.attached/app0.service.d/20-portable.conf

grep -q -F "LogExtraFields=PORTABLE=app1" /run/systemd/system.attached/app1.service.d/20-portable.conf
grep -q -F "LogExtraFields=PORTABLE_ROOT=rootdir" /run/systemd/system.attached/app1.service.d/20-portable.conf
grep -q -F "LogExtraFields=PORTABLE_EXTENSION=app0" /run/systemd/system.attached/app1.service.d/20-portable.conf
grep -q -F "LogExtraFields=PORTABLE_EXTENSION_NAME_AND_VERSION=app" /run/systemd/system.attached/app1.service.d/20-portable.conf
grep -q -F "LogExtraFields=PORTABLE_EXTENSION=app1" /run/systemd/system.attached/app1.service.d/20-portable.conf
grep -q -F "LogExtraFields=PORTABLE_EXTENSION_NAME_AND_VERSION=app_1" /run/systemd/system.attached/app1.service.d/20-portable.conf

portablectl detach --clean --now --runtime --extension /tmp/app0 --extension /tmp/app1 /tmp/rootdir app0 app1

# Ensure --clean remove state and other directories belonging to the portable image being detached
test ! -d /var/lib/app0
test ! -d /run/app0

# Ensure that mixed mode copies the images and units (client-owned) but symlinks the profile (OS owned)
portablectl "${ARGS[@]}" attach --copy=mixed --runtime --extension /tmp/app0 --extension /tmp/app1 /tmp/rootdir app0 app1
test -d /run/portables/app0
test -d /run/portables/app1
test -d /run/portables/rootdir
test -f /run/systemd/system.attached/app0.service
test -f /run/systemd/system.attached/app1.service
test -L /run/systemd/system.attached/app0.service.d/10-profile.conf
test -L /run/systemd/system.attached/app1.service.d/10-profile.conf
portablectl detach --runtime --extension /tmp/app0 --extension /tmp/app1 /tmp/rootdir app0 app1

# Ensure that --force works with directory extensions, and that ExtensionDirectories=
# is not decorated with :x-systemd.relax-extension-release-check
portablectl "${ARGS[@]}" attach --force --copy=symlink --now --runtime --extension /tmp/app0 /tmp/rootdir app0

systemctl is-active app0.service
status="$(portablectl is-attached --extension app0 rootdir)"
[[ "${status}" == "running-runtime" ]]

grep -q -F "ExtensionDirectories=" /run/systemd/system.attached/app0.service.d/20-portable.conf
(! grep -q -F "x-systemd.relax-extension-release-check" /run/systemd/system.attached/app0.service.d/20-portable.conf)

portablectl detach --now --runtime --extension /tmp/app0 /tmp/rootdir app0

# Attempt to disable the app unit during detaching. Requires --copy=symlink to reproduce.
# Provides coverage for https://github.com/systemd/systemd/issues/23481
portablectl "${ARGS[@]}" attach --copy=symlink --now --runtime /tmp/rootdir minimal-app0
portablectl detach --now --runtime --enable /tmp/rootdir minimal-app0
# attach and detach again to check if all drop-in configs are removed even if the main unit files are removed
portablectl "${ARGS[@]}" attach --copy=symlink --now --runtime /tmp/rootdir minimal-app0
portablectl detach --now --runtime --enable /tmp/rootdir minimal-app0

# The wrong file should be ignored, given the right one has the xattr set
trap 'rm -rf /var/cache/wrongext' EXIT
mkdir -p /var/cache/wrongext/usr/lib/extension-release.d /var/cache/wrongext/usr/lib/systemd/system/
echo "[Service]" >/var/cache/wrongext/usr/lib/systemd/system/app0.service
touch /var/cache/wrongext/usr/lib/extension-release.d/extension-release.wrongext_somethingwrong.txt
cp /tmp/rootdir/usr/lib/os-release /var/cache/wrongext/usr/lib/extension-release.d/extension-release.app0
setfattr -n user.extension-release.strict -v "false" /var/cache/wrongext/usr/lib/extension-release.d/extension-release.app0
portablectl "${ARGS[@]}" attach --runtime --extension /var/cache/wrongext /tmp/rootdir app0
status="$(portablectl is-attached --extension wrongext rootdir)"
[[ "${status}" == "attached-runtime" ]]
portablectl detach --runtime --extension /var/cache/wrongext /tmp/rootdir app0

umount /tmp/rootdir
umount /tmp/app0
umount /tmp/app1
