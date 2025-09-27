#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eux

if ! command -v musl-gcc 2>/dev/null; then
    echo "musl-gcc is not installed, skipping the test."
    exit 0
fi

. /etc/os-release

TMPDIR=$(mktemp -d)

cleanup() (
    set +e

    if [[ -d "$TMPDIR" ]]; then
        rm -rf "$TMPDIR"
    fi
)

trap cleanup EXIT ERR INT TERM

mkdir -p "${TMPDIR}/build"
mkdir -p "${TMPDIR}/include"

CFLAGS="-idirafter ${TMPDIR}/include"

LINKS=(
    acl
    archive.h
    archive_entry.h
    asm-generic
    audit-records.h
    audit_logging.h
    bpf
    bzlib.h
    dwarf.h
    elfutils
    fido.h
    gcrypt.h
    gelf.h
    gnutls
    idn2.h
    libaudit.h
    libcryptsetup.h
    libelf.h
    libkmod.h
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

if [[ "$ID" == arch ]]; then
    LINKS+=(
        asm
        curl
        gpg-error.h
        libiptc
        linux
    )
elif [[ "$ID" == centos ]]; then
    LINKS+=(
        asm
        curl
        gpg-error.h
        linux
        selinux
    )
elif [[ "$ID" == fedora ]]; then
    LINKS+=(
        asm
        curl
        gpg-error.h
        libiptc
        linux
        selinux
    )
elif [[ "$ID" == debian ]] || [[ "$ID" == ubuntu ]]; then
    # Currently, debian/ubuntu does not provide crypt.h for musl. Hence, this does not work.

    CFLAGS="$CFLAGS -idirafter /usr/include/$(uname -m)-linux-gnu"

    LINKS+=(
        linux
        selinux
        sys/apparmor.h
    )
fi

for t in "${LINKS[@]}"; do
    [[ -e "/usr/include/$t" ]]
    link="${TMPDIR}/include/${t}"
    mkdir -p "${link%/*}"
    ln -s "/usr/include/$t" "$link"
done

env CC=musl-gcc \
    CXX=musl-gcc \
    CFLAGS="$CFLAGS" \
    CXXFLAGS="$CFLAGS" \
    meson setup --werror -Ddbus-interfaces-dir=no -Dlibc=musl "${TMPDIR}/build"

ninja -v -C "${TMPDIR}/build"
