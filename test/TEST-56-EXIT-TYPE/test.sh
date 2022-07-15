#!/usr/bin/env bash
set -e

TEST_DESCRIPTION="test ExitType=cgroup"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

if [[ "$(get_cgroup_hierarchy)" != unified ]]; then
    echo "This test requires unified cgroup hierarchy, skipping..."
    exit 0
fi

do_test "$@"
