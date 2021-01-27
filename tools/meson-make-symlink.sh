#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu

if [ "${MESON_INSTALL_QUIET:-0}" = 1 ] ; then
    VERBOSE=""
else
    VERBOSE="v"
fi

# this is needed mostly because $DESTDIR is provided as a variable,
# and we need to create the target directory...

mkdir -${VERBOSE}p "$(dirname "${DESTDIR:-}$2")"
if [ "$(dirname $1)" = . -o "$(dirname $1)" = .. ]; then
    ln -${VERBOSE}fs -T -- "$1" "${DESTDIR:-}$2"
else
    ln -${VERBOSE}fs -T --relative -- "${DESTDIR:-}$1" "${DESTDIR:-}$2"
fi
