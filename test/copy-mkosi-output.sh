#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
mkosi_output_path="$1"
output="$2"
lockfile="$(dirname "$output")/.$(basename "$output").lock"
exec 3<>"$lockfile"
if flock --exclusive --nonblock 3; then
	truncate --size=0 "$lockfile"
	echo $$ >&3
else
	echo "$output already being written to by $(cat "$lockfile")" >&2
	exit 1
fi
temp_copy="$(dirname "$output")/.$(basename "$output").tmp.$$"
trap 'rm -rf "$temp_copy"' EXIT
if [[ "$EUID" -ne 0 ]]; then
    mkdir -p "$temp_copy"
    for e in "$mkosi_output_path"/*; do
        if [[ ! -d "$e" ]]; then
            cp -a "$e" "$temp_copy/."
            continue
        fi
        unshare --map-auto --map-root-user cp -a --reflink=auto "$e" "$temp_copy/."
    done
else
    cp -a --reflink=auto "$mkosi_output_path" "$temp_copy"
fi
rm -rf "$output"
mv "$temp_copy" "$output"
sync
