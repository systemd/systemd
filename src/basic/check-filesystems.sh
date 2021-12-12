#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu
set -o pipefail

cpp="$1"
filesystems_gperf="$2"
shift 2

includes=""
for i in "$@"; do
    includes="$includes -include $i"
done

error=false

# shellcheck disable=SC2086
for fs in $($cpp -dM $includes - </dev/null | \
            grep -E '_MAGIC' | \
            grep -vE 'LINUX_MAGIC' | \
            awk '/^#define[ \t]+[A-Z0-9_]+MAGIC[ \t]+/ { print $2; }'); do
    if ! grep -E "\{.*$fs.*\}" "$filesystems_gperf" >/dev/null; then
        # STACK_END_MAGIC doesn't refer to a filesystem
        # mtd_inode was removed in 2015
        # futexfs was removed in 2018
        if [[ "$fs" =~ ^(STACK_END_MAGIC|MTD_INODE_FS_MAGIC|FUTEXFS_SUPER_MAGIC)$ ]]; then
            continue
        fi
        echo "Filesystem found in kernel header but not in $(basename "$filesystems_gperf"): $fs";
        error=true
    fi
done

if $error; then
    exit 1
fi
