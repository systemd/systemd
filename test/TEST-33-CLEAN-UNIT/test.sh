#!/usr/bin/env bash
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
set -e
TEST_DESCRIPTION="test CleanUnit"
. $(dirname ${BASH_SOURCE[0]})/../test-functions

do_test "$@" 33
