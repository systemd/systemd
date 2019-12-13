#!/bin/sh
set -eu

cd "$MESON_SOURCE_ROOT"

if [ ! -f .git/hooks/pre-commit.sample -o -f .git/hooks/pre-commit ]; then
    exit 2 # not needed
fi

cp -p .git/hooks/pre-commit.sample .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
echo 'Activated pre-commit hook'
