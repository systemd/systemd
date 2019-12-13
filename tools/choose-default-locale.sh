#!/bin/sh
set -e

# Fedora uses C.utf8 but Debian uses C.UTF-8
if locale -a | grep -xq -E 'C\.(utf8|UTF-8)'; then
    echo 'C.UTF-8'
elif locale -a | grep -xqF 'en_US.utf8'; then
    echo 'en_US.UTF-8'
else
    echo 'C'
fi
