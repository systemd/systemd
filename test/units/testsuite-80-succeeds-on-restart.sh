#!/usr/bin/env bash
if [[ ! -f "/testsuite-80-required.ko" ]]
then
    touch "/testsuite-80-required.ko"
    exit 1
fi
