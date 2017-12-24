#!/bin/sh
set -eu

cpp="$1"
shift

includes=""
for i in "$@"; do
        includes="$includes -include $i"
done

$cpp -dM $includes - </dev/null | \
        grep -vE 'AUDIT_.*(FIRST|LAST)_' | \
        sed -r -n 's/^#define\s+AUDIT_(\w+)\s+([0-9]{4})\s*$$/\1\t\2/p' | \
        sort -k2
