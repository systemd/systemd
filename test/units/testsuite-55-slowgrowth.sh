#!/usr/bin/env bash
set -eu -o pipefail

PAGE_SIZE=$(getconf PAGE_SIZE)
BLOAT_ITERATION_TARGET=$(( 100 << 20 )) # 100 MB
BLOAT_HOLDER=()
PID="$$"

function bloat {
        local set_size=$(cat "/proc/$PID/statm" | cut -d " " -f2)
        local mem_usage=$(( "$set_size" * "$PAGE_SIZE" ))
        local target_mem_size=$(( "$mem_usage" + "$1" ))

        BLOAT_HOLDER=()
        while [[ "$mem_usage" -lt "$target_mem_size" ]]; do
                echo "target $target_mem_size"
                echo "mem usage $mem_usage"
                BLOAT_HOLDER+=( $(printf "%0.sg" {1..1000000}) )
                set_size=$(cat "/proc/$PID/statm" | cut -d " " -f2)
                mem_usage=$(( "$set_size" * "$PAGE_SIZE" ))
        done
}

function run {
        local arr=()

        while [[ true ]]; do
                bloat "$BLOAT_ITERATION_TARGET"
                arr+=( "$BLOAT_HOLDER" )
                sleep 1
        done
}

run
