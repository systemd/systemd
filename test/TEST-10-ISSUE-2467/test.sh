#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="https://github.com/systemd/systemd/issues/2467"

. $(dirname ${BASH_SOURCE[0]})/../test-functions

do_test "$@" 10
