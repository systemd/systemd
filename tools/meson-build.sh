#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux

sourcedir="${1:?}"
builddir="${2:?}"
target="${3:?}"
c_args="${4:?}"
cpp_args="${5:?}"
options="${6:?}"
CC="${7:?}"
CXX="$8"

if [ ! -f "$builddir/build.ninja" ]; then
    # shellcheck disable=SC2086
    CC="$CC" CXX="$CXX" meson setup -Dc_args="$c_args" -Dcpp_args="$cpp_args" "$builddir" "$sourcedir" $options
fi

ninja -C "$builddir" "$target"
