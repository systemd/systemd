#!/usr/bin/env bash

set -eux
set -o pipefail

testcase_megasas() {
    lsblk -S
    [[ "$(lsblk -S | wc -l)" -ge 64 ]]
}

: >/failed

udevadm settle

lsblk -a

# TEST_FUNCTION_NAME is passed on the kernel command line via systemd.setenv=
# in the respective test.sh file
if ! command -v "${TEST_FUNCTION_NAME:?}"; then
    echo >&2 "Missing verification handler for test case '$TEST_FUNCTION_NAME'"
    exit 1
fi

echo "TEST_FUNCTION_NAME=$TEST_FUNCTION_NAME"
"$TEST_FUNCTION_NAME"

touch /testok
rm /failed
