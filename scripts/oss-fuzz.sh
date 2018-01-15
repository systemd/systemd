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

meson $WORK -Doss-fuzz=true -Db_lundef=false
ninja -C $WORK fuzzers

# get DNS packet corpus
df=$WORK/dns-fuzzing
rm -rf $df
git clone --depth 1 https://github.com/CZ-NIC/dns-fuzzing $df
zip -jqr $OUT/fuzz-dns-packet_seed_corpus.zip $df/packet

mkdir -p $OUT/src/shared
mv $WORK/src/shared/libsystemd-shared-*.so $OUT/src/shared

find $WORK -maxdepth 1 -type f -executable -name "fuzz-*" -exec mv {} $OUT \;
mv $WORK/*.so src/fuzz/*.options $OUT
