#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu

git shortlog --author=noreply@weblate.org --invert-grep -s `git describe --abbrev=0 --match 'v[0-9][0-9][0-9]'`.. | \
    awk '{ $1=""; print $0 "," }' | \
    sort -u
