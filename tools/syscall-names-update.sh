#!/bin/sh
set -eu

cd "$1"

curl -L -o syscall-names.text 'https://raw.githubusercontent.com/hrw/syscalls-table/master/syscall-names.text'
