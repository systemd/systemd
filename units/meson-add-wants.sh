#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2154,SC2174
set -eu

i=1
while [ $i -lt $# ] ; do
    eval unitdir="\${$i}"
    eval target="\${$((i + 1))}"
    eval unit="\${$((i + 2))}"

    if [ "${MESON_INSTALL_QUIET:-0}" = 1 ] ; then
        VERBOSE=""
    else
        VERBOSE="v"
    fi

    case "$target" in
        */?*) # a path, but not just a slash at the end
            dir="${DESTDIR:-}${target}"
            ;;
        *)
            dir="${DESTDIR:-}${unitdir}/${target}"
            ;;
    esac

    unitpath="${DESTDIR:-}${unitdir}/${unit}"

    case "$target" in
        */)
            mkdir -${VERBOSE}p -m 0755 "$dir"
            ;;
        *)
            mkdir -${VERBOSE}p -m 0755 "$(dirname "$dir")"
            ;;
    esac

    ln -${VERBOSE}fs --relative "$unitpath" "$dir"

    i=$((i + 3))
done
