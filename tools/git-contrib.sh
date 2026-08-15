#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu

tag="$(git describe --abbrev=0 --match 'v[0-9][0-9][0-9]')"
git shortlog -s --group=author --group=trailer:Co-authored-by "${tag}.." |
    sed -e 's/^[[:space:]]*[0-9]*[[:space:]]*//; /Weblate/ d; /dependabot\[bot\]/ d; s/ / /g; s/--/-/g; s/.*/\0,/' |
    tr '\n' ' ' | sed -e "s/^/Contributions from: /g" -e "s/,\s*$/\n/g" | fold -w 72 -s |
    sed -e "s/^/        /g" -e "s/\s*$//g"
