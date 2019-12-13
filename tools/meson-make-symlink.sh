#!/bin/sh
set -eu

# this is needed mostly because $DESTDIR is provided as a variable,
# and we need to create the target directory...

mkdir -vp "$(dirname "${DESTDIR:-}$2")"
if [ "$(dirname $1)" = . ]; then
    ln -vfs -T "$1" "${DESTDIR:-}$2"
else
    ln -vfs -T --relative "${DESTDIR:-}$1" "${DESTDIR:-}$2"
fi
