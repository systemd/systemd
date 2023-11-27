#!/bin/sh
set -eux

system_mkosi="$(readlink -f "$1")"
testunit="$2"
shift 2
case "$1" in
'--credential-tmpfile')
    path="$2"
    contents="$3"
    shift 3
    set -- "$@" --credential="tmpfiles.extra='f~ $path 644 root root - $(base64 -w 0 "$contents")'"
    ;;
*)
    ;;
esac
set -- "$@" "--kernel-command-line-extra=systemd.emergency=exit"

mkosi_output_path="$(dirname "$system_mkosi")/$testunit"
rm -rf "$mkosi_output_path"
"$(dirname "$0")/copy-mkosi-output.sh" "$system_mkosi" "$mkosi_output_path"

runmkosi() {
    mkosi -C .. --image=system --format=disk --output-dir="$mkosi_output_path" "$@"
}

machine_id="$(basename "$mkosi_output_path" | sha1sum | sed 's/^\(.\{32\}\).*$/\1/')"
echo Using machine-id "$machine_id" for test
image_path="$(readlink -f "$(runmkosi --json summary | jq --raw-output --arg image system '.Images[]|select(.Image==$image)|@text "\(.OutputDirectory)/\(.Output)"')")"
runmkosi --qemu-smp=2 --qemu-mem=2G "$@" --credential "system.machine_id=$machine_id" qemu

if systemd-dissect --with "$image_path" test -e testok; then
    # Remove on success so that less space is required to run the whole suite
    rm -rf "$mkosi_output_path"
    exit 0
else
    exit_code="$?"
    runmkosi journalctl -b -u "$testunit"
    exit "$exit_code"
fi
