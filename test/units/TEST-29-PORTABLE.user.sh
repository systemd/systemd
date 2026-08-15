#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
# shellcheck disable=SC2233,SC2235
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

if [[ ! -f /usr/lib/systemd/system/systemd-mountfsd.socket ]] ||
   [[ ! -f /usr/lib/systemd/system/systemd-nsresourced.socket ]] ||
   ! command -v mksquashfs ||
   ! grep -q bpf /sys/kernel/security/lsm ||
   ! find /usr/lib* -name libbpf.so.1 2>/dev/null | grep . ||
   systemd-analyze compare-versions "$(uname -r)" lt 6.5 ||
   systemd-analyze compare-versions "$(pkcheck --version | awk '{print $3}')" lt 124 ||
   systemctl --version | grep -- "-BTF" >/dev/null; then
    echo "Skipping mountfsd/nsresourced tests"
    exit 0
fi

systemctl start systemd-mountfsd.socket systemd-nsresourced.socket

# Arrays cannot be exported, so redefine in each test script
ARGS=()
if [[ -v ASAN_OPTIONS || -v UBSAN_OPTIONS ]]; then
    # If we're running under sanitizers, we need to use a less restrictive
    # profile, otherwise LSan syscall would get blocked by seccomp
    ARGS+=(--profile=trusted)
fi

# To be able to mount images as an unprivileged user we need verity sidecars so generate them for app1 which
# doesn't have them by default.
veritysetup format /tmp/app1.raw /tmp/app1.verity --root-hash-file /tmp/app1.roothash
openssl smime -sign -nocerts -noattr -binary \
    -in /tmp/app1.roothash \
    -inkey /usr/share/mkosi.key \
    -signer /usr/share/mkosi.crt \
    -outform der \
    -out /tmp/app1.roothash.p7s
chmod go+r /tmp/app1*

at_exit() {
    set +e

    rm -f /tmp/app1.verity /tmp/app1.roothash /tmp/app1.roothash.p7s
    loginctl disable-linger testuser
}

trap at_exit EXIT

# For unprivileged user manager
loginctl enable-linger testuser

systemctl start user@4711.service

portablectl_user() {
    runas testuser env XDG_RUNTIME_DIR=/run/user/4711 portablectl --user "$@"
}

busctl_user() {
    runas testuser env XDG_RUNTIME_DIR=/run/user/4711 busctl --user "$@"
}

systemctl_user() {
    runas testuser env XDG_RUNTIME_DIR=/run/user/4711 systemctl --user "$@"
}

runas_user() {
    runas testuser env XDG_RUNTIME_DIR=/run/user/4711 "$@"
}

# Start the user portable daemon
systemctl_user start dbus-org.freedesktop.portable1.service

: "Test basic attach, reattach and detach for user portable services"

portablectl_user "${ARGS[@]}" attach --now --runtime /usr/share/minimal_0.raw minimal-app0

portablectl_user is-attached minimal-app0
portablectl_user inspect /usr/share/minimal_0.raw minimal-app0.service
systemctl_user is-active minimal-app0.service
systemctl_user is-active minimal-app0-foo.service
systemctl_user is-active minimal-app0-bar.service && exit 1

# Ensure pinning by policy works
cat /run/user/4711/systemd/user.attached/minimal-app0-foo.service.d/20-portable.conf
grep -q -F 'root=signed+squashfs:' /run/user/4711/systemd/user.attached/minimal-app0-foo.service.d/20-portable.conf

portablectl_user "${ARGS[@]}" reattach --now --runtime /usr/share/minimal_1.raw minimal-app0

portablectl_user is-attached minimal-app0
portablectl_user inspect /usr/share/minimal_0.raw minimal-app0.service
systemctl_user is-active minimal-app0.service
systemctl_user is-active minimal-app0-bar.service
systemctl_user is-active minimal-app0-foo.service && exit 1

portablectl_user list | grep -F "minimal_1" >/dev/null
busctl_user tree org.freedesktop.portable1 --no-pager | grep -F '/org/freedesktop/portable1/image/minimal_5f1' >/dev/null

portablectl_user detach --now --runtime /usr/share/minimal_1.raw minimal-app0

portablectl_user list | grep -F "No images." >/dev/null
busctl_user tree org.freedesktop.portable1 --no-pager | grep -F '/org/freedesktop/portable1/image/minimal_5f1' && exit 1 >/dev/null

: "Test --force for user portable services"

runas_user mkdir -p /run/user/4711/systemd/user.attached/minimal-app0.service.d/
runas_user tee /run/user/4711/systemd/user.attached/minimal-app0.service >/dev/null <<EOF
[Unit]
Description=Minimal App 0
EOF
runas_user tee /run/user/4711/systemd/user.attached/minimal-app0.service.d/10-profile.conf >/dev/null <<EOF
[Unit]
Description=Minimal App 0
EOF
runas_user tee /run/user/4711/systemd/user.attached/minimal-app0.service.d/20-portable.conf >/dev/null <<EOF
[Unit]
Description=Minimal App 0
EOF
systemctl_user daemon-reload

portablectl_user "${ARGS[@]}" attach --force --now --runtime /usr/share/minimal_0.raw minimal-app0

portablectl_user is-attached --force minimal-app0
portablectl_user inspect --force /usr/share/minimal_0.raw minimal-app0.service
systemctl_user is-active minimal-app0.service
systemctl_user is-active minimal-app0-foo.service
systemctl_user is-active minimal-app0-bar.service && exit 1

portablectl_user "${ARGS[@]}" reattach --force --now --runtime /usr/share/minimal_1.raw minimal-app0

portablectl_user is-attached --force minimal-app0
portablectl_user inspect --force /usr/share/minimal_0.raw minimal-app0.service
systemctl_user is-active minimal-app0.service
systemctl_user is-active minimal-app0-bar.service
systemctl_user is-active minimal-app0-foo.service && exit 1

portablectl_user list | grep -F "minimal_1" >/dev/null
busctl_user tree org.freedesktop.portable1 --no-pager | grep -F '/org/freedesktop/portable1/image/minimal_5f1' >/dev/null

portablectl_user detach --force --now --runtime /usr/share/minimal_1.raw minimal-app0

portablectl_user list | grep -F "No images." >/dev/null
busctl_user tree org.freedesktop.portable1 --no-pager | grep -F '/org/freedesktop/portable1/image/minimal_5f1' && exit 1 >/dev/null

: "Test extension images for user portable services"

portablectl_user "${ARGS[@]}" attach --now --runtime --extension /tmp/app0.raw /usr/share/minimal_0.raw app0

systemctl_user is-active app0.service
status="$(portablectl_user is-attached --extension app0 minimal_0)"
[[ "${status}" == "running-runtime" ]]

grep -q -F "LogExtraFields=PORTABLE_ROOT=minimal_0.raw" /run/user/4711/systemd/user.attached/app0.service.d/20-portable.conf
grep -q -F "LogExtraFields=PORTABLE_EXTENSION=app0.raw" /run/user/4711/systemd/user.attached/app0.service.d/20-portable.conf
grep -q -F "LogExtraFields=PORTABLE_EXTENSION_NAME_AND_VERSION=app" /run/user/4711/systemd/user.attached/app0.service.d/20-portable.conf
# Ensure pinning by policy works
grep -q -F 'RootImagePolicy=root=signed+squashfs:' /run/user/4711/systemd/user.attached/app0.service.d/20-portable.conf >/dev/null
grep -q -F 'ExtensionImagePolicy=root=signed+squashfs:' /run/user/4711/systemd/user.attached/app0.service.d/20-portable.conf >/dev/null

portablectl_user "${ARGS[@]}" reattach --now --runtime --extension /tmp/app0.raw /usr/share/minimal_1.raw app0

systemctl_user is-active app0.service
status="$(portablectl_user is-attached --extension app0 minimal_1)"
[[ "${status}" == "running-runtime" ]]

grep -q -F "LogExtraFields=PORTABLE_ROOT=minimal_1.raw" /run/user/4711/systemd/user.attached/app0.service.d/20-portable.conf
grep -q -F "LogExtraFields=PORTABLE_EXTENSION=app0.raw" /run/user/4711/systemd/user.attached/app0.service.d/20-portable.conf
grep -q -F "LogExtraFields=PORTABLE_EXTENSION_NAME_AND_VERSION=app" /run/user/4711/systemd/user.attached/app0.service.d/20-portable.conf

portablectl_user detach --now --runtime --extension /tmp/app0.raw /usr/share/minimal_1.raw app0

: "Test versioned extension images for user portable services"

cp /tmp/app0.raw /tmp/app0_1.0.raw
cp /tmp/app0.verity /tmp/app0_1.0.verity
cp /tmp/app0.roothash /tmp/app0_1.0.roothash
cp /tmp/app0.roothash.p7s /tmp/app0_1.0.roothash.p7s
portablectl_user "${ARGS[@]}" attach --now --runtime --extension /tmp/app0_1.0.raw /usr/share/minimal_0.raw app0

systemctl_user is-active app0.service
status="$(portablectl_user is-attached --extension app0_1 minimal_0)"
[[ "${status}" == "running-runtime" ]]

portablectl_user detach --now --runtime --extension /tmp/app0_1.0.raw /usr/share/minimal_1.raw app0
rm -f /tmp/app0_1.0*

: "Test reattach with version changes for user portable services"

portablectl_user "${ARGS[@]}" attach --now --runtime --extension /tmp/app1.raw /usr/share/minimal_0.raw app1

systemctl_user is-active app1.service
status="$(portablectl_user is-attached --extension app1 minimal_0)"
[[ "${status}" == "running-runtime" ]]

# Ensure that adding or removing a version to the image doesn't break reattaching
cp /tmp/app1.raw /tmp/app1_2.raw
cp /tmp/app1.verity /tmp/app1_2.verity
cp /tmp/app1.roothash /tmp/app1_2.roothash
cp /tmp/app1.roothash.p7s /tmp/app1_2.roothash.p7s
portablectl_user "${ARGS[@]}" reattach --now --runtime --extension /tmp/app1_2.raw /usr/share/minimal_1.raw app1

systemctl_user is-active app1.service
status="$(portablectl_user is-attached --extension app1_2 minimal_1)"
[[ "${status}" == "running-runtime" ]]

portablectl_user "${ARGS[@]}" reattach --now --runtime --extension /tmp/app1.raw /usr/share/minimal_1.raw app1

systemctl_user is-active app1.service
status="$(portablectl_user is-attached --extension app1 minimal_1)"
[[ "${status}" == "running-runtime" ]]

portablectl_user detach --now --runtime --extension /tmp/app1.raw /usr/share/minimal_1.raw app1

: "Test --no-reload for user portable services"

portablectl_user "${ARGS[@]}" attach --now --runtime --extension /tmp/app1.raw /usr/share/minimal_0.raw app1

systemctl_user is-active app1.service
status="$(portablectl_user is-attached --extension app1 minimal_0)"
[[ "${status}" == "running-runtime" ]]

portablectl_user detach --force --no-reload --runtime --extension /tmp/app1.raw /usr/share/minimal_0.raw app1
portablectl_user "${ARGS[@]}" attach --force --no-reload --runtime --extension /tmp/app1.raw /usr/share/minimal_0.raw app1
systemctl_user daemon-reload
systemctl_user restart app1.service

systemctl_user is-active app1.service
status="$(portablectl_user is-attached --extension app1 minimal_0)"
[[ "${status}" == "running-runtime" ]]

portablectl_user detach --now --runtime --extension /tmp/app1.raw /usr/share/minimal_0.raw app1

# : "Test vpick for user portable services"

mkdir -p /tmp/app1.v/
cp /tmp/app1.raw /tmp/app1.v/app1_1.0.raw
cp /tmp/app1.verity /tmp/app1.v/app1_1.0.verity
cp /tmp/app1.roothash /tmp/app1.v/app1_1.0.roothash
cp /tmp/app1.roothash.p7s /tmp/app1.v/app1_1.0.roothash.p7s
cp /tmp/app1_2.raw /tmp/app1.v/app1_2.0.raw
cp /tmp/app1_2.verity /tmp/app1.v/app1_2.0.verity
cp /tmp/app1_2.roothash /tmp/app1.v/app1_2.0.roothash
cp /tmp/app1_2.roothash.p7s /tmp/app1.v/app1_2.0.roothash.p7s
portablectl_user "${ARGS[@]}" attach --now --runtime --extension /tmp/app1.v/ /usr/share/minimal_1.raw app1

systemctl_user is-active app1.service
status="$(portablectl_user is-attached --extension app1_2.0.raw minimal_1)"
[[ "${status}" == "running-runtime" ]]

rm -f /tmp/app1.v/app1_2.0*
portablectl_user "${ARGS[@]}" reattach --now --runtime --extension /tmp/app1.v/ /usr/share/minimal_1.raw app1

systemctl_user is-active app1.service
status="$(portablectl_user is-attached --extension app1_1.0.raw minimal_1)"
[[ "${status}" == "running-runtime" ]]

portablectl_user detach --now --runtime --extension /tmp/app1.v/ /usr/share/minimal_0.raw app1
rm -f /tmp/app1.v/app1_1.0*

: "Test extension-release.NAME override for user portable services"

cp /tmp/app0.raw /tmp/app10.raw
cp /tmp/app0.verity /tmp/app10.verity
cp /tmp/app0.roothash /tmp/app10.roothash
cp /tmp/app0.roothash.p7s /tmp/app10.roothash.p7s
portablectl_user "${ARGS[@]}" attach --force --now --runtime --extension /tmp/app10.raw /usr/share/minimal_0.raw app0

systemctl_user is-active app0.service
status="$(portablectl_user is-attached --extension /tmp/app10.raw /usr/share/minimal_0.raw)"
[[ "${status}" == "running-runtime" ]]

portablectl_user inspect --force --cat --extension /tmp/app10.raw /usr/share/minimal_0.raw app0 | grep -F "Extension Release: /tmp/app10.raw" >/dev/null

# Ensure that we can detach even when an image has been deleted already (stop the unit manually as
# portablectl won't find it)
rm -f /tmp/app10*
systemctl_user stop app0.service
portablectl_user detach --force --runtime --extension /tmp/app10.raw /usr/share/minimal_0.raw app0

: "Test confext images for user portable services"

portablectl_user "${ARGS[@]}" attach --now --runtime --extension /tmp/app0.raw --extension /tmp/conf0.raw /usr/share/minimal_0.raw app0

systemctl_user is-active app0.service
status="$(portablectl_user is-attached --extension /tmp/app0.raw --extension /tmp/conf0.raw /usr/share/minimal_0.raw)"
[[ "${status}" == "running-runtime" ]]

portablectl_user inspect --force --cat --extension /tmp/app0.raw --extension /tmp/conf0.raw /usr/share/minimal_0.raw app0 | grep -F "Extension Release: /tmp/conf0.raw" >/dev/null

portablectl_user detach --now --runtime --extension /tmp/app0.raw --extension /tmp/conf0.raw /usr/share/minimal_0.raw app0

: "Test multiple portables sharing the same base image for user portable services"

portablectl_user "${ARGS[@]}" attach --runtime --extension /tmp/app0.raw /usr/share/minimal_0.raw app0
portablectl_user "${ARGS[@]}" attach --runtime --extension /tmp/app1.raw /usr/share/minimal_0.raw app1

status="$(portablectl_user is-attached --extension app0 minimal_0)"
[[ "${status}" == "attached-runtime" ]]
status="$(portablectl_user is-attached --extension app1 minimal_0)"
[[ "${status}" == "attached-runtime" ]]

(! portablectl_user detach --runtime /usr/share/minimal_0.raw app)

status="$(portablectl_user is-attached --extension app0 minimal_0)"
[[ "${status}" == "attached-runtime" ]]
status="$(portablectl_user is-attached --extension app1 minimal_0)"
[[ "${status}" == "attached-runtime" ]]

# Ensure 'portablectl list' shows the correct status for both images
portablectl_user list
portablectl_user list | grep -F "minimal_0" | grep -F "attached-runtime" >/dev/null
portablectl_user list | grep -F "app0" | grep -F "attached-runtime" >/dev/null
portablectl_user list | grep -F "app1" | grep -F "attached-runtime" >/dev/null

portablectl_user detach --runtime --extension /tmp/app0.raw /usr/share/minimal_0.raw app

status="$(portablectl_user is-attached --extension app1 minimal_0)"
[[ "${status}" == "attached-runtime" ]]

portablectl_user detach --runtime --extension /tmp/app1.raw /usr/share/minimal_0.raw app
