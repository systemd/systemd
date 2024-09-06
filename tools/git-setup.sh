#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu

cd "${MESON_SOURCE_ROOT:?}"

ret=2

if [ -f .git/hooks/pre-commit.sample ] && [ ! -f .git/hooks/pre-commit ]; then
    cp -p .git/hooks/pre-commit.sample .git/hooks/pre-commit
    chmod +x .git/hooks/pre-commit
    echo 'Activated pre-commit hook'
    ret=0
fi

exit $ret
