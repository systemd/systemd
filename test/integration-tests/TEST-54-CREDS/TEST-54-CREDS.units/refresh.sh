#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

OUTPUT_FILE="$1"

dump_creds_tree() {
    grep . "$CREDENTIALS_DIRECTORY"/* >"$OUTPUT_FILE"
}

on_sighup() {
    systemd-notify --reloading
    dump_creds_tree
    systemd-notify --ready
}

trap on_sighup SIGINT

export SYSTEMD_LOG_LEVEL=debug

dump_creds_tree
sleep infinity &
systemd-notify --ready

while :; do
    wait
done
