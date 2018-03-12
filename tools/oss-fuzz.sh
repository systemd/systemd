#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1+
#
# Copyright 2017 Jonathan Rudenberg
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

set -ex

export LC_CTYPE=C.UTF-8

export CC=${CC:-clang}
export CXX=${CXX:-clang++}
clang_version="$($CC --version | sed -nr 's/.*version ([^ ]+?) .*/\1/p' | sed -r 's/-$//')"

SANITIZER=${SANITIZER:-address -fsanitize-address-use-after-scope}
flags="-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=$SANITIZER -fsanitize-coverage=trace-pc-guard,trace-cmp"

clang_lib="/usr/lib64/clang/${clang_version}/lib/linux"
[ -d "$clang_lib" ] || clang_lib="/usr/lib/clang/${clang_version}/lib/linux"

export CFLAGS=${CFLAGS:-$flags}
export CXXFLAGS=${CXXFLAGS:-$flags}
export LDFLAGS=${LDFLAGS:--L${clang_lib}}

export WORK=${WORK:-$(pwd)}
export OUT=${OUT:-$(pwd)/out}
mkdir -p $OUT

build=$WORK/build
rm -rf $build
mkdir -p $build

fuzzflag="oss-fuzz=true"
if [ -z "$FUZZING_ENGINE" ]; then
        fuzzflag="llvm-fuzz=true"
fi

meson $build -D$fuzzflag -Db_lundef=false
ninja -C $build fuzzers

for d in "$(dirname "$0")/../test/fuzz-corpus/"*; do
        zip -jqr $OUT/fuzz-$(basename "$d")_seed_corpus.zip "$d"
done

# get fuzz-dns-packet corpus
df=$build/dns-fuzzing
git clone --depth 1 https://github.com/CZ-NIC/dns-fuzzing $df
zip -jqr $OUT/fuzz-dns-packet_seed_corpus.zip $df/packet

mkdir -p $OUT/src/shared
mv $build/src/shared/libsystemd-shared-*.so $OUT/src/shared

find $build -maxdepth 1 -type f -executable -name "fuzz-*" -exec mv {} $OUT \;
cp src/fuzz/*.options $OUT
