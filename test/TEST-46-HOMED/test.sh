#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="testing homed"
TEST_NO_QEMU=1

. $(dirname ${BASH_SOURCE[0]})/../test-functions

do_test "$@" 46
