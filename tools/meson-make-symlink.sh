#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu

SOURCE="${1:?}"
TARGET="${2:?}"

if [ "${MESON_INSTALL_QUIET:-0}" = 1 ] ; then
    VERBOSE=""
else
    VERBOSE="v"
fi

# this is needed mostly because $DESTDIR is provided as a variable,
# and we need to create the target directory...

mkdir -${VERBOSE}p "$(dirname "${DESTDIR:-}$TARGET")"
if [ "$(dirname "$SOURCE")" = . ] || [ "$(dirname "$SOURCE")" = .. ]; then
    ln -${VERBOSE}fs -T -- "$SOURCE" "${DESTDIR:-}$TARGET"
else
    ln -${VERBOSE}fs -T --relative -- "${DESTDIR:-}$SOURCE" "${DESTDIR:-}$TARGET"
fi
