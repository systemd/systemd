#!/bin/sh
set -eu

git shortlog -s `git describe --abbrev=0`.. | \
    awk '{ $1=""; print $0 "," }' | \
    sort -u
