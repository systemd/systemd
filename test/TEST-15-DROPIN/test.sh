#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="Dropin tests"
TEST_NO_QEMU=1

. $(dirname ${BASH_SOURCE[0]})/../test-functions

do_test "$@" 15
