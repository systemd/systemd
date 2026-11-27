#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu
set -o pipefail

# Make sure readelf's output is not locale dependent.
export LANG=C LC_ALL=C

PE="${1:?}"
ELF="${2:?}"

if ! command -v readelf >/dev/null; then
    echo "readelf not found, skipping" >&2
    exit 77
fi

if ! readelf_out="$(readelf -n "$ELF")"; then
    echo "readelf failed on $ELF" >&2
    exit 1
fi

# elf2efi.py only embeds a CodeView GUID for a 16-byte (md5) build-id; mirror that here.
build_id="$(sed -n 's/.*Build ID: \([0-9a-f]\{32\}\)$/\1/p;T;q' <<<"$readelf_out")"
if [[ -z "$build_id" ]]; then
    echo "$ELF has no usable build-id, nothing to cross-check" >&2
    exit 77
fi

if ! command -v objdump >/dev/null; then
    echo "objdump not found, skipping" >&2
    exit 77
fi

if ! objdump_out="$(objdump -p "$PE")"; then
    echo "objdump could not parse $PE, missing binutils PE support? Skipping." >&2
    exit 77
fi

signature="$(sed -n 's/.*RSDS signature \([0-9a-f]*\).*/\1/p;T;q' <<<"$objdump_out")"
if [[ -z "$signature" ]]; then
    echo "objdump found no RSDS CodeView signature in $PE" >&2
    exit 1
fi

if [[ "$signature" != "$build_id" ]]; then
    echo "objdump-reported CodeView signature $signature does not match ELF build-id $build_id" >&2
    exit 1
fi

echo "CodeView GUID $signature matches ELF build-id"
