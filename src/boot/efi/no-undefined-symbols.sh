#!/bin/sh
set -eu

if nm -D -u "$1" | grep ' U '; then
    echo "Undefined symbols detected!"
    exit 1
fi
