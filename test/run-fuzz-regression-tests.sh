#!/bin/bash -ex
# SPDX-License-Identifier: LGPL-2.1+
#
# Copyright 2018 Jonathan Rudenberg
#
# systemd is free software; you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation; either version 2.1 of the License, or
# (at your option) any later version.
#
# systemd is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with systemd; If not, see <http://www.gnu.org/licenses/>.

TEST_DIR="$(dirname "$0")/fuzz-regressions"

if ! "$CC" --version | grep -q clang; then
        echo '$CC must be clang'
        exit 1
fi

if ! "$CXX" --version | grep -q clang; then
        echo '$CXX must be clang'
        exit 1
fi

for sanitizer in `ls "$TEST_DIR"`; do
        dir="$(dirname "$0")/../build-clang-$sanitizer"
        mkdir -p "$dir"
        meson "$dir" -Db_lundef=false -Db_sanitize=$sanitizer
        ninja -C "$dir" fuzzers

        for t in `ls "$TEST_DIR/$sanitizer"`; do
                "$dir/fuzz-$t" "$TEST_DIR/$sanitizer/$t/"*
        done
done
