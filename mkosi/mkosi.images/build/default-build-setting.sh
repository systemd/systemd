#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

# This is intended to be included by mkosi.build.chroot,
# and sets the following variables:
# - $MKOSI_CFLAGS
# - $MKOSI_LDFLAGS
# - $MKOSI_MESON_OPTIONS

MKOSI_CFLAGS="-O0 -g"
if ((LLVM)); then
    # TODO: Remove -fno-sanitize-function when https://github.com/systemd/systemd/issues/29972 is fixed.
    MKOSI_CFLAGS="$MKOSI_CFLAGS -shared-libasan -fno-sanitize=function"
fi

MKOSI_LDFLAGS=""
if ((LLVM)) && [[ -n "$SANITIZERS" ]]; then
    MKOSI_LDFLAGS="$MKOSI_LDFLAGS -Wl,-rpath=$(realpath "$(clang --print-runtime-dir)")"
fi

MKOSI_MESON_OPTIONS="-D mode=developer -D vcs-tag=${VCS_TAG:-true} -D b_sanitize=${SANITIZERS:-none} -Dtime-epoch=1744207869"
if ((WIPE)) && [[ -d "$BUILDDIR/meson-private" ]]; then
    MKOSI_MESON_OPTIONS="$MKOSI_MESON_OPTIONS --wipe"
fi

if ((COVERAGE)); then
    MKOSI_MESON_OPTIONS="$MKOSI_MESON_OPTIONS -D b_coverage=true"
    MKOSI_CFLAGS="$MKOSI_CFLAGS -fprofile-dir=/coverage"
fi
