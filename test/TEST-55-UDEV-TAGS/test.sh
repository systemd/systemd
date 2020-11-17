#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="UDEV tags management"
TEST_NO_NSPAWN=1

. $(dirname ${BASH_SOURCE[0]})/../test-functions

do_test "$@" 55
