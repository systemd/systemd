#!/bin/sh
set -eux

system_mkosi="$(readlink -f "$1")"
testunit="$2"
shift 2

mkosi_output_path="$(dirname "$system_mkosi")/$testunit"
[ -e "$mkosi_output_path" ] || cp -a --reflink=always "$system_mkosi" "$mkosi_output_path"

runmkosi() {
    mkosi -C .. --image=system --output-dir="$mkosi_output_path" "$@"
}

image_path="$(runmkosi --json summary | jq --raw-output --arg image system '.Images[]|select(.Image==$image)|@text "\(.OutputDirectory)/\(.Output)"')"
runmkosi --qemu-smp=1 --qemu-mem=1G "--kernel-command-line-extra=$*" qemu

if systemd-dissect --with "$image_path" test -e testok; then
    # Remove on success so that less space is required to run the whole suite
    rm -rf "$mkosi_output_path"
    exit 0
else
    exit_code="$?"
    runmkosi journalctl -b -u "$testunit"
    exit "$exit_code"
fi
