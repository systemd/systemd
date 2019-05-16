#!/bin/bash

set -eu

for i in *.h */*.h; do
    if [[ $i == 'wireguard.h' ]]; then
        curl https://raw.githubusercontent.com/WireGuard/WireGuard/master/src/uapi/$i -o $i
    else
        curl https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/linux/$i -o $i
    fi

    sed -i -e 's/__user //g' -e '/^#include <linux\/compiler.h>/ d' $i
done
