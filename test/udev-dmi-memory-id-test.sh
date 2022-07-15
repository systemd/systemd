#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later

set -e

dmi_memory_id="$1"
input="$2"
expected="$3"

output=$(mktemp --tmpdir "test-udev-dmi-memory-id.XXXXXXXXXX")
# shellcheck disable=SC2064
trap "rm '$output'" EXIT INT QUIT PIPE

(
    set -x
    "$dmi_memory_id" -F "$input" >"$output"
    diff -u "$output" "$expected"
)
