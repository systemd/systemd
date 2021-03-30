#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu

tag="$(git describe --abbrev=0 --match 'v[0-9][0-9][0-9]')"
git log --pretty=tformat:%aN --author=noreply@weblate.org --invert-grep -s "${tag}.." | \
    sed 's/ / /g; s/--/-/g; s/.*/        \0,/' |
    sort -u
