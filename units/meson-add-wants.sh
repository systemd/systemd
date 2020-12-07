#!/bin/sh
set -eu

unitdir="$1"
target="$2"
unit="$3"

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
