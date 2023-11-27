#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
output="$1"
mkosi -C .. --image=system --format=disk --without-tests -fi build
mkosi_output_path="$(mkosi -C .. --json summary | jq --raw-output --arg image system '.Images[]|select(.Image==$image)|.OutputDirectory')"
"$(dirname "$0")/copy-mkosi-output.sh" "$mkosi_output_path" "$output"
