#!/bin/sh
set -eu

git shortlog -s `git describe --abbrev=0`.. | \
    cut -c8- | \
    sed 's/ / /g' | \
    awk '{ print $$0 "," }' | \
    sed -e 's/ / /g' | \
    sort -u
