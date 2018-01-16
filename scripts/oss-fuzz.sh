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

if [ -z "$WORK" ]; then
         echo '$WORK must be set'
         exit 1
fi
build=$WORK/build
rm -rf $build
mkdir -p $build

meson $build -Doss-fuzz=true -Db_lundef=false
ninja -C $build fuzzers

# get DNS packet corpus
df=$build/dns-fuzzing
git clone --depth 1 https://github.com/CZ-NIC/dns-fuzzing $df
zip -jqr $OUT/fuzz-dns-packet_seed_corpus.zip $df/packet

mkdir -p $OUT/src/shared
mv $build/src/shared/libsystemd-shared-*.so $OUT/src/shared

find $build -maxdepth 1 -type f -executable -name "fuzz-*" -exec mv {} $OUT \;
mv $build/*.so src/fuzz/*.options $OUT
