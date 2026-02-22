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

portablectl "${ARGS[@]}" attach --now --runtime /usr/share/minimal_0.raw minimal-app0

portablectl is-attached minimal-app0
portablectl inspect /usr/share/minimal_0.raw minimal-app0.service
systemctl is-active minimal-app0.service
systemctl is-active minimal-app0-foo.service
systemctl is-active minimal-app0-bar.service && exit 1

# Ensure pinning by policy works
cat /run/systemd/system.attached/minimal-app0-foo.service.d/20-portable.conf
grep -q -F 'root=signed+squashfs:' /run/systemd/system.attached/minimal-app0-foo.service.d/20-portable.conf

portablectl "${ARGS[@]}" reattach --now --runtime /usr/share/minimal_1.raw minimal-app0

portablectl is-attached minimal-app0
portablectl inspect /usr/share/minimal_0.raw minimal-app0.service
systemctl is-active minimal-app0.service
systemctl is-active minimal-app0-bar.service
systemctl is-active minimal-app0-foo.service && exit 1

portablectl list | grep -F "minimal_1" >/dev/null
busctl tree org.freedesktop.portable1 --no-pager | grep -F '/org/freedesktop/portable1/image/minimal_5f1' >/dev/null

portablectl detach --now --runtime /usr/share/minimal_1.raw minimal-app0

portablectl list | grep -F "No images." >/dev/null
busctl tree org.freedesktop.portable1 --no-pager | grep -F '/org/freedesktop/portable1/image/minimal_5f1' && exit 1 >/dev/null

# Ensure we don't regress (again) when using --force

mkdir -p /run/systemd/system.attached/minimal-app0.service.d/
cat <<EOF >/run/systemd/system.attached/minimal-app0.service
[Unit]
Description=Minimal App 0
EOF
cat <<EOF >/run/systemd/system.attached/minimal-app0.service.d/10-profile.conf
[Unit]
Description=Minimal App 0
EOF
cat <<EOF >/run/systemd/system.attached/minimal-app0.service.d/20-portable.conf
[Unit]
Description=Minimal App 0
EOF
systemctl daemon-reload

portablectl "${ARGS[@]}" attach --force --now --runtime /usr/share/minimal_0.raw minimal-app0

portablectl is-attached --force minimal-app0
portablectl inspect --force /usr/share/minimal_0.raw minimal-app0.service
systemctl is-active minimal-app0.service
systemctl is-active minimal-app0-foo.service
systemctl is-active minimal-app0-bar.service && exit 1

portablectl "${ARGS[@]}" reattach --force --now --runtime /usr/share/minimal_1.raw minimal-app0

portablectl is-attached --force minimal-app0
portablectl inspect --force /usr/share/minimal_0.raw minimal-app0.service
systemctl is-active minimal-app0.service
systemctl is-active minimal-app0-bar.service
systemctl is-active minimal-app0-foo.service && exit 1

portablectl list | grep -F "minimal_1" >/dev/null
busctl tree org.freedesktop.portable1 --no-pager | grep -F '/org/freedesktop/portable1/image/minimal_5f1' >/dev/null

portablectl detach --force --now --runtime /usr/share/minimal_1.raw minimal-app0

portablectl list | grep -F "No images." >/dev/null
busctl tree org.freedesktop.portable1 --no-pager | grep -F '/org/freedesktop/portable1/image/minimal_5f1' >/dev/null && exit 1

portablectl "${ARGS[@]}" attach --now --runtime --extension /tmp/app0.raw /usr/share/minimal_0.raw app0

systemctl is-active app0.service
status="$(portablectl is-attached --extension app0 minimal_0)"
[[ "${status}" == "running-runtime" ]]

grep -q -F "LogExtraFields=PORTABLE_ROOT=minimal_0.raw" /run/systemd/system.attached/app0.service.d/20-portable.conf
grep -q -F "LogExtraFields=PORTABLE_EXTENSION=app0.raw" /run/systemd/system.attached/app0.service.d/20-portable.conf
grep -q -F "LogExtraFields=PORTABLE_EXTENSION_NAME_AND_VERSION=app" /run/systemd/system.attached/app0.service.d/20-portable.conf
# Ensure pinning by policy works
grep -q -F 'RootImagePolicy=root=signed+squashfs:' /run/systemd/system.attached/app0.service.d/20-portable.conf >/dev/null
grep -q -F 'ExtensionImagePolicy=root=signed+squashfs:' /run/systemd/system.attached/app0.service.d/20-portable.conf >/dev/null

portablectl "${ARGS[@]}" reattach --now --runtime --extension /tmp/app0.raw /usr/share/minimal_1.raw app0

systemctl is-active app0.service
status="$(portablectl is-attached --extension app0 minimal_1)"
[[ "${status}" == "running-runtime" ]]

grep -q -F "LogExtraFields=PORTABLE_ROOT=minimal_1.raw" /run/systemd/system.attached/app0.service.d/20-portable.conf
grep -q -F "LogExtraFields=PORTABLE_EXTENSION=app0.raw" /run/systemd/system.attached/app0.service.d/20-portable.conf
grep -q -F "LogExtraFields=PORTABLE_EXTENSION_NAME_AND_VERSION=app" /run/systemd/system.attached/app0.service.d/20-portable.conf

portablectl detach --now --runtime --extension /tmp/app0.raw /usr/share/minimal_1.raw app0

# Ensure versioned images are accepted without needing to use --force to override the extension-release
# matching

cp /tmp/app0.raw /tmp/app0_1.0.raw
portablectl "${ARGS[@]}" attach --now --runtime --extension /tmp/app0_1.0.raw /usr/share/minimal_0.raw app0

systemctl is-active app0.service
status="$(portablectl is-attached --extension app0_1 minimal_0)"
[[ "${status}" == "running-runtime" ]]

portablectl detach --now --runtime --extension /tmp/app0_1.0.raw /usr/share/minimal_1.raw app0
rm -f /tmp/app0_1.0.raw

portablectl "${ARGS[@]}" attach --now --runtime --extension /tmp/app1.raw /usr/share/minimal_0.raw app1

systemctl is-active app1.service
status="$(portablectl is-attached --extension app1 minimal_0)"
[[ "${status}" == "running-runtime" ]]

# Ensure that adding or removing a version to the image doesn't break reattaching
cp /tmp/app1.raw /tmp/app1_2.raw
portablectl "${ARGS[@]}" reattach --now --runtime --extension /tmp/app1_2.raw /usr/share/minimal_1.raw app1

systemctl is-active app1.service
status="$(portablectl is-attached --extension app1_2 minimal_1)"
[[ "${status}" == "running-runtime" ]]

portablectl "${ARGS[@]}" reattach --now --runtime --extension /tmp/app1.raw /usr/share/minimal_1.raw app1

systemctl is-active app1.service
status="$(portablectl is-attached --extension app1 minimal_1)"
[[ "${status}" == "running-runtime" ]]

portablectl detach --force --no-reload --runtime --extension /tmp/app1.raw /usr/share/minimal_1.raw app1
portablectl "${ARGS[@]}" attach --force --no-reload --runtime --extension /tmp/app1.raw /usr/share/minimal_0.raw app1
systemctl daemon-reload
systemctl restart app1.service

systemctl is-active app1.service
status="$(portablectl is-attached --extension app1 minimal_0)"
[[ "${status}" == "running-runtime" ]]

portablectl detach --now --runtime --extension /tmp/app1.raw /usr/share/minimal_0.raw app1

# Ensure vpick works, including reattaching to a new image
mkdir -p /tmp/app1.v/
cp /tmp/app1.raw /tmp/app1.v/app1_1.0.raw
cp /tmp/app1_2.raw /tmp/app1.v/app1_2.0.raw
portablectl "${ARGS[@]}" attach --now --runtime --extension /tmp/app1.v/ /usr/share/minimal_1.raw app1

systemctl is-active app1.service
status="$(portablectl is-attached --extension app1_2.0.raw minimal_1)"
[[ "${status}" == "running-runtime" ]]

rm -f /tmp/app1.v/app1_2.0.raw
portablectl "${ARGS[@]}" reattach --now --runtime --extension /tmp/app1.v/ /usr/share/minimal_1.raw app1

systemctl is-active app1.service
status="$(portablectl is-attached --extension app1_1.0.raw minimal_1)"
[[ "${status}" == "running-runtime" ]]

portablectl detach --now --runtime --extension /tmp/app1.v/ /usr/share/minimal_0.raw app1
rm -f /tmp/app1.v/app1_1.0.raw

# Ensure that the combination of read-only images, state directory and dynamic user works, and that
# state is retained. Check after detaching, as on slow systems (eg: sanitizers) it might take a while
# after the service is attached before the file appears.
grep -q -F bar "${STATE_DIRECTORY}/app0/foo"
grep -q -F baz "${STATE_DIRECTORY}/app1/foo"

# Ensure that we can override the check on extension-release.NAME
cp /tmp/app0.raw /tmp/app10.raw
portablectl "${ARGS[@]}" attach --force --now --runtime --extension /tmp/app10.raw /usr/share/minimal_0.raw app0

systemctl is-active app0.service
status="$(portablectl is-attached --extension /tmp/app10.raw /usr/share/minimal_0.raw)"
[[ "${status}" == "running-runtime" ]]

# Ensure --force adds relax-extension-release-check for image extensions
grep -q -F "ExtensionImages=" /run/systemd/system.attached/app0.service.d/20-portable.conf
grep -q -F "ExtensionImagePolicy=" /run/systemd/system.attached/app0.service.d/20-portable.conf

portablectl inspect --force --cat --extension /tmp/app10.raw /usr/share/minimal_0.raw app0 | grep -F "Extension Release: /tmp/app10.raw" >/dev/null

# Ensure that we can detach even when an image has been deleted already (stop the unit manually as
# portablectl won't find it)
rm -f /tmp/app10.raw
systemctl stop app0.service
portablectl detach --force --runtime --extension /tmp/app10.raw /usr/share/minimal_0.raw app0

# portablectl also accepts confexts
portablectl "${ARGS[@]}" attach --now --runtime --extension /tmp/app0.raw --extension /tmp/conf0.raw /usr/share/minimal_0.raw app0

systemctl is-active app0.service
status="$(portablectl is-attached --extension /tmp/app0.raw --extension /tmp/conf0.raw /usr/share/minimal_0.raw)"
[[ "${status}" == "running-runtime" ]]

portablectl inspect --force --cat --extension /tmp/app0.raw --extension /tmp/conf0.raw /usr/share/minimal_0.raw app0 | grep -F "Extension Release: /tmp/conf0.raw" >/dev/null

portablectl detach --now --runtime --extension /tmp/app0.raw --extension /tmp/conf0.raw /usr/share/minimal_0.raw app0

# Ensure that mixed mode copies the images and units (client-owned) but symlinks the profile (OS owned)
portablectl "${ARGS[@]}" attach --copy=mixed --runtime --extension /tmp/app0.raw /usr/share/minimal_0.raw app0
test -f /run/portables/app0.raw
test -f /run/portables/minimal_0.raw
test -f /run/systemd/system.attached/app0.service
test -L /run/systemd/system.attached/app0.service.d/10-profile.conf
portablectl detach --runtime --extension /tmp/app0.raw /usr/share/minimal_0.raw app0

# Ensure that when two portables share the same base image, removing one doesn't remove the other too

portablectl "${ARGS[@]}" attach --runtime --extension /tmp/app0.raw /usr/share/minimal_0.raw app0
portablectl "${ARGS[@]}" attach --runtime --extension /tmp/app1.raw /usr/share/minimal_0.raw app1

status="$(portablectl is-attached --extension app0 minimal_0)"
[[ "${status}" == "attached-runtime" ]]
status="$(portablectl is-attached --extension app1 minimal_0)"
[[ "${status}" == "attached-runtime" ]]

(! portablectl detach --runtime /usr/share/minimal_0.raw app)

status="$(portablectl is-attached --extension app0 minimal_0)"
[[ "${status}" == "attached-runtime" ]]
status="$(portablectl is-attached --extension app1 minimal_0)"
[[ "${status}" == "attached-runtime" ]]

# Ensure 'portablectl list' shows the correct status for both images
portablectl list
portablectl list | grep -F "minimal_0" | grep -F "attached-runtime" >/dev/null
portablectl list | grep -F "app0" | grep -F "attached-runtime" >/dev/null
portablectl list | grep -F "app1" | grep -F "attached-runtime" >/dev/null

portablectl detach --runtime --extension /tmp/app0.raw /usr/share/minimal_0.raw app

status="$(portablectl is-attached --extension app1 minimal_0)"
[[ "${status}" == "attached-runtime" ]]

portablectl detach --runtime --extension /tmp/app1.raw /usr/share/minimal_0.raw app

# Ensure that when mixing directory and image extensions, ExtensionImagePolicy= is only
# applied to image extensions and not to directory extensions
mkdir -p /tmp/app1
mount /tmp/app1.raw /tmp/app1
portablectl "${ARGS[@]}" attach --copy=symlink --now --runtime --extension /tmp/app1 --extension /tmp/app0.raw /usr/share/minimal_0.raw app0

systemctl is-active app0.service

grep -q -F "ExtensionDirectories=/tmp/app1" /run/systemd/system.attached/app0.service.d/20-portable.conf
grep -q -F "ExtensionImages=/tmp/app0.raw" /run/systemd/system.attached/app0.service.d/20-portable.conf
# ExtensionImagePolicy= should appear exactly once (for the image, not the directory)
[[ "$(grep -c -F "ExtensionImagePolicy=" /run/systemd/system.attached/app0.service.d/20-portable.conf)" == "1" ]]

portablectl detach --now --runtime --extension /tmp/app1 --extension /tmp/app0.raw /usr/share/minimal_0.raw app0
umount -l /tmp/app1
