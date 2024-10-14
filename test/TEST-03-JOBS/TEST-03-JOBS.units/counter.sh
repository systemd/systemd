#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex

COUNT="$(<"$1")"
(( COUNT++ ))
echo "$COUNT" >"$1"
