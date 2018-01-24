#!/bin/sh

set -eu

for symbol in `nm -g --defined-only "$@" | grep " T " | cut -d" " -f3 | sort -u` ; do
        if test -f ${MESON_BUILD_ROOT}/man/$symbol.3 ; then
                echo "✓ Symbol $symbol() is documented."
        else
                printf "  \x1b[1;31mSymbol $symbol() lacks documentation.\x1b[0m\n"
        fi
done
