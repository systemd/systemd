#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="https://github.com/systemd/systemd/issues/1981"
TEST_NO_QEMU=1

. $(dirname ${BASH_SOURCE[0]})/../test-functions

NSPAWN_TIMEOUT=30

do_test "$@" 07
