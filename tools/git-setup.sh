#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu

cd "${MESON_SOURCE_ROOT:?}"

if [ -e .git ]; then
    git config submodule.recurse true
    git config fetch.recurseSubmodules on-demand
    git config push.recurseSubmodules no
fi

ret=2

if [ -f .git/hooks/pre-commit.sample ] && [ ! -f .git/hooks/pre-commit ]; then
    cp -p .git/hooks/pre-commit.sample .git/hooks/pre-commit
    chmod +x .git/hooks/pre-commit
    echo 'Activated pre-commit hook'
    ret=0
fi

if [ ! -f .git/hooks/post-rewrite ]; then
    cp -p tools/git-submodule-update-hook.sh .git/hooks/post-rewrite
    echo 'Activated post-rewrite hook'
    ret=0
fi

if [ ! -f .git/hooks/post-checkout ]; then
    cp -p tools/git-submodule-update-hook.sh .git/hooks/post-checkout
    echo 'Activated post-checkout hook'
    ret=0
fi

exit $ret
