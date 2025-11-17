#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eux

if ! command -v musl-gcc >/dev/null; then
    echo "musl-gcc is not installed, skipping the test."
    exit 77
fi

TMPDIR=$(mktemp -d)

cleanup() (
    set +e

    if [[ -d "$TMPDIR" ]]; then
        rm -rf "$TMPDIR"
    fi
)

trap cleanup EXIT ERR INT TERM

mkdir -p "${TMPDIR}/build"
mkdir -p "${TMPDIR}/usr/include"
mkdir -p "${TMPDIR}/usr/lib64/pkgconfig"

CFLAGS="-idirafter ${TMPDIR}/usr/include"
export PKG_CONFIG_PATH="${TMPDIR}"/usr/lib64/pkgconfig

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
    link="${TMPDIR}"/usr/include/"${t}"
    mkdir -p "${link%/*}"
    ln -s /usr/include/"$t" "$link"
done

env \
    CC=musl-gcc \
    CXX=musl-gcc \
    CFLAGS="$CFLAGS" \
    CXXFLAGS="$CFLAGS" \
    meson setup --werror -Ddbus-interfaces-dir=no -Dlibc=musl "${TMPDIR}"/build

ninja -v -C "${TMPDIR}"/build
