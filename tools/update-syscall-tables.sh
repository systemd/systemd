#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu

cd "${1:?}" && shift

curl --fail -L -o syscall-list.txt 'https://raw.githubusercontent.com/hrw/syscalls-table/master/data/syscall-names.text'

for arch in "$@"; do
    curl --fail -L -o "syscalls-$arch.txt" "https://raw.githubusercontent.com/hrw/syscalls-table/master/data/tables/syscalls-$arch"
done
