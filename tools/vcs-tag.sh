#!/bin/bash
set -e

MODE="$1"

if [[ -d .git ]] && ! git describe --tags --exact-match &>/dev/null; then
    if [[ "$MODE" == "developer" ]]; then
        DIRTY="--dirty=^"
    else
        DIRTY=""
    fi

    echo "-g$(git describe --abbrev=7 --match="" --always $DIRTY)"
fi
