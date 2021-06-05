#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu

"$@" '-' -o/dev/null </dev/null
