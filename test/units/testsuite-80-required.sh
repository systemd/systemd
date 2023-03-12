#!/usr/bin/env bash
if [[ ! -f "$workspace/testsuite-80-required.ko" ]]
then
    touch "$workspace/testsuite-80-required.ko"
    exit 1
fi
