#!/bin/sh
set -eux

image="$1"
testunit="$2"
shift 2

image_path="$(mkosi -C .. --json summary | jq --raw-output --arg image "$image" '.Images[]|select(.Image==$image)|@text "\(.OutputDirectory)/\(.Output)"')"
systemd-dissect --with "$image_path" rm -rf testok var/tmp/scratch

mkosi -C .. --image="$image" "$@"

if systemd-dissect --with "$image_path" sh -c 'if [ -e testok ]; then rm testok && exit 0; else exit 1; fi'; then
    exit 0
else
    exit_code="$?"
    mkosi -C .. --image="$image" journalctl -b -u "$testunit"
    exit "$exit_code"
fi
