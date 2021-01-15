#!/bin/sh
set -eu

cd "$1" && shift

curl -L -o syscall-names.text 'https://raw.githubusercontent.com/hrw/syscalls-table/master/syscall-names.text'

for arch in "$@"; do
    curl -L -o syscalls-$arch "https://raw.githubusercontent.com/hrw/syscalls-table/master/tables/syscalls-$arch"
done
