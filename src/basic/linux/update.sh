#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu

for i in *.h */*.h; do
    if [[ $i == 'loadavg.h' ]]; then
        curl --fail https://raw.githubusercontent.com/torvalds/linux/master/include/linux/sched/$i -o $i
    else
        curl --fail https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/linux/$i -o $i
    fi

    sed -i -e 's/__user //g' -e '/^#include <linux\/compiler.h>/ d' $i
done
