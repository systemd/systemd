#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="https://github.com/systemd/systemd/issues/3171"
TEST_NO_QEMU=1

. $(dirname ${BASH_SOURCE[0]})/../test-functions

do_test "$@" 12
