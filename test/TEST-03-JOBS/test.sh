#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="Job-related tests"
TEST_NO_QEMU=1
IMAGE_NAME="default"

. $(dirname ${BASH_SOURCE[0]})/../test-functions

do_test "$@" 03
