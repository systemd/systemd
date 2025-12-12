#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later

# Usage:
#   tools/setup-musl-build.sh <build-directory> <options…>
# E.g.
#   tools/setup-musl-build.sh build-musl -Dbuildtype=debugoptimized && ninja -C build-musl

set -eu

BUILD_DIR="${1:?}"
shift

SETUP_DIR="${BUILD_DIR}/extra"

LINKS=(
    acl
    archive.h
    archive_entry.h
    asm
    asm-generic
    audit-records.h
    audit_logging.h
    bpf
    bzlib.h
    curl
    dwarf.h
    elfutils
    fido.h
    gcrypt.h
    gelf.h
    gnutls
    gpg-error.h
    idn2.h
    libaudit.h
    libcryptsetup.h
    libelf.h
    libkmod.h
    linux
    lz4.h
    lz4frame.h
    lz4hc.h
    lzma
    lzma.h
    microhttpd.h
    mtd
    openssl
    pcre2.h
    pwquality.h
    qrencode.h
    seccomp-syscalls.h
    seccomp.h
    security
    selinux
    sys/acl.h
    sys/capability.h
    tss2
    xen
    xkbcommon
    zconf.h
    zlib.h
    zstd.h
    zstd_errors.h
)

for t in "${LINKS[@]}"; do
    [[ -e /usr/include/"$t" ]]
    link="${SETUP_DIR}/usr/include/${t}"
    mkdir -p "${link%/*}"
    ln -s /usr/include/"$t" "$link"
done

# Use an absolute path so that when we chdir into the build directory,
# the path still works. This is easier than figuring out the relative path.
[[ "${SETUP_DIR}" =~ ^/ ]] || SETUP_DIR="${PWD}/${SETUP_DIR}"

CFLAGS="-idirafter ${SETUP_DIR}/usr/include"

set -x
env \
    CC=musl-gcc \
    CXX=musl-gcc \
    CFLAGS="$CFLAGS" \
    CXXFLAGS="$CFLAGS" \
    meson setup -Ddbus-interfaces-dir=no -Dlibc=musl "${BUILD_DIR}" "${@}"
