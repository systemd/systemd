#!/usr/bin/env bash

set -eux
set -o pipefail

testcase_megasas2() {
    lsblk -S
    [[ "$(lsblk --scsi --noheadings | wc -l)" -ge 128 ]]
}

testcase_nvme() {
    lsblk -S
    [[ "$(lsblk --noheadings | grep "^nvme" | wc -l)" -ge 28 ]]
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

systemctl status systemd-udevd

touch /testok
rm /failed
