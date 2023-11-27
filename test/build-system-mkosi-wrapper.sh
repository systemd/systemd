#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
image="$1"
output="$2"
shift 2
mkdir -p "$output"
mkosi -C .. --image="$image" --format=disk --output-dir="$(readlink -f "$output")" --without-tests -fi "$@" build
