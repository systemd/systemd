#!/bin/sh
set -eu

git shortlog -s `git describe --abbrev=0 --match 'v[0-9][0-9][0-9]'`.. | \
    awk '{ $1=""; print $0 "," }' | \
    sort -u
