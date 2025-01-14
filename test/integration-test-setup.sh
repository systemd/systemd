#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu
set -o pipefail

case "$1" in
    setup)
        if [[ -f "$STATE_DIRECTORY/inprogress" ]]; then
            exit 0
        fi

        if [[ -d /snapshot ]]; then
            echo "Run systemctl soft-reboot first to make sure the test runs within a pristine rootfs" >&2
            exit 1
        fi

        . /usr/lib/os-release

        if test -n "$(shopt -s nullglob; echo /work/build/*.{rpm,deb,pkg.tar})"; then
            case "$ID" in
                arch)
                    pacman --upgrade --needed --noconfirm /work/build/*.pkg.tar
                    ;;
                debian|ubuntu)
                    apt-get install /work/build/*.deb
                    ;;
                opensuse*)
                    zypper --non-interactive install --allow-unsigned-rpm /work/build/*.rpm
                    ;;
                centos|fedora)
                    dnf upgrade --assumeyes --disablerepo="*" /work/build/*.rpm
                    ;;
                *)
                    echo "Unknown distribution $ID" >&2
                    exit 1
            esac
        fi

        # TODO: Use a proper flat btrfs subvolume layout once we can create subvolumes without privileged in
        # systemd-repart (see https://github.com/systemd/systemd/pull/33498). Until that's possible, we nest
        # snapshots within each other.
        if command -v btrfs >/dev/null && [[ "$(stat --file-system --format %T /)" == "btrfs" ]]; then
            btrfs subvolume snapshot / /snapshot
        fi

        touch "$STATE_DIRECTORY/inprogress"
        ;;
    finalize)
        # If we're rebooting, the test does a reboot as part of its execution and we shouldn't remove /inprogress.
        if ! [[ "$(systemctl list-jobs)" =~ reboot.target|kexec.target|soft-reboot.target ]]; then
            rm -f "$STATE_DIRECTORY/inprogress"
        fi
        ;;
    *)
        echo "Unknown verb $1" >&2
        exit 1
esac
