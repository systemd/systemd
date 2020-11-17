#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="Tmpfiles related tests"
TEST_NO_QEMU=1
. $(dirname ${BASH_SOURCE[0]})/../test-functions

do_test "$@" 22
