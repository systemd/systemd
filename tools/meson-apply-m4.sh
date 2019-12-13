#!/bin/sh
set -eu

CONFIG=$1
TARGET=$2

if [ $# -ne 2 ]; then
    echo 'Invalid number of arguments.'
    exit 1
fi

if [ ! -f $CONFIG ]; then
    echo "$CONFIG not found."
    exit 2
fi

if [ ! -f $TARGET ]; then
    echo "$TARGET not found."
    exit 3
fi

DEFINES=$(awk '$1 == "#define" && $3 == "1" { printf "-D%s ", $2 }' $CONFIG)

m4 -P $DEFINES $TARGET
