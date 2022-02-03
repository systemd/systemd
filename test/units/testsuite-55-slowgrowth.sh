#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Don't use set -x here, since it generates a lot of output and slows
# the script down, causing unexpected test fails.
set -eu
set -o pipefail

PAGE_SIZE=$(getconf PAGE_SIZE)
BLOAT_ITERATION_TARGET=$((100 << 20)) # 100 MB
BLOAT_HOLDER=()
PID="$$"

function bloat {
        local set_size mem_usage target_mem_size

        set_size=$(cut -d " " -f2 "/proc/$PID/statm")
        mem_usage=$((set_size * PAGE_SIZE))
        target_mem_size=$((mem_usage + $1))

        BLOAT_HOLDER=()
        while [[ "$mem_usage" -lt "$target_mem_size" ]]; do
                echo "target $target_mem_size"
                echo "mem usage $mem_usage"
                BLOAT_HOLDER+=("$(printf "=%0.s" {1..1000000})")
                set_size=$(cut -d " " -f2 "/proc/$PID/statm")
                mem_usage=$((set_size * PAGE_SIZE))
        done
}

function run {
        local arr=()

        while :; do
                bloat "$BLOAT_ITERATION_TARGET"
                arr+=("${BLOAT_HOLDER[@]}")
                sleep 1
        done
}

run
