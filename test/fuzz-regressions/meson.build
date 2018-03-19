# SPDX-License-Identifier: LGPL-2.1+
#
# Copyright 2018 Zbigniew Jędrzejewski-Szmek
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

sanitize_address = custom_target(
        'sanitize-address-fuzzers',
        output : 'sanitize-address-fuzzers',
        command : [meson_build_sh,
                   meson.source_root(),
                   '@OUTPUT@',
                   'fuzzers',
                   '-Db_lundef=false -Db_sanitize=address'])

sanitizers = [['address', sanitize_address]]

fuzz_regression_tests = '''
        fuzz-dns-packet/oss-fuzz-5465
        fuzz-dns-packet/issue-7888
        fuzz-unit-file/oss-fuzz-6884
        fuzz-unit-file/oss-fuzz-6885
        fuzz-unit-file/oss-fuzz-6886
        fuzz-unit-file/oss-fuzz-6892
        fuzz-unit-file/oss-fuzz-6897
        fuzz-unit-file/oss-fuzz-6897-evverx
        fuzz-unit-file/oss-fuzz-6908
        fuzz-unit-file/oss-fuzz-6917
        fuzz-unit-file/oss-fuzz-6977
        fuzz-unit-file/oss-fuzz-7004
'''.split()
