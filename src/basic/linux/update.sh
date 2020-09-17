#!/usr/bin/env bash

set -eu

for i in *.h */*.h; do
    curl https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/linux/$i -o $i

    sed -i -e 's/__user //g' -e '/^#include <linux\/compiler.h>/ d' $i
done
