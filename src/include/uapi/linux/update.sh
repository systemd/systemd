#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu
set -o pipefail

# The directory must be userspace kernel header directory:
# git clone git@github.com:torvalds/linux.git
# make -C linux headers
# ./update.sh linux
SRCDIR=${1?}

for i in *.h */*.h; do
    if [[ "$i" == bpf_insn.h ]]; then
        cp "$SRCDIR/samples/bpf/$i" "$i"
    else
        cp "$SRCDIR/usr/include/linux/$i" "$i"
    fi

    case "$i" in
        auto_dev-ioctl.h)
            # set AUTOFS_DEV_IOCTL_VERSION_MINOR to 1, bumped by 3dd8f7c3b78b9556582fd64bf5c9986723f9dca1 (v4.14)
            sed -r -i '/^#define[[:space:]]+AUTOFS_DEV_IOCTL_VERSION_MINOR/ s/[0-9]+/1/' "$i"
            ;;
        dm-ioctl.h)
            # set DM_VERSION_MINOR to 41, bumped by afa179eb603847494aa5061d4f501224a30dd187 (v5.4)
            sed -r -i '/^#define[[:space:]]+DM_VERSION_MINOR/ s/[0-9]+/41/' "$i"
            # also update DM_VERSION_EXTRA to make it match with the minor version
            sed -r -i '/^#define[[:space:]]+DM_VERSION_EXTRA/ s/"-ioctl \([0-9-]*\)"/"-ioctl (2019-09-16)"/' "$i"
            ;;
        ethtool.h)
            # add casts in ethtool_cmd_speed()
            sed -r -i '/return (ep->speed_hi << 16) | ep->speed;/ s/return .*;/return ((__u32) ep->speed_hi << 16) | (__u32) ep->speed;/' "$i"
            ;;
    esac
done
