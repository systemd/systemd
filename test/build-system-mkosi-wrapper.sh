#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
output="$1"
mkosi -C .. --image=system --without-tests -f build
mkosi_output_path="$(mkosi -C .. --json summary | jq --raw-output --arg image system '.Images[]|select(.Image==$image)|.OutputDirectory')"
cp -a --reflink=auto "$mkosi_output_path" "$output"
