# SPDX-License-Identifier: LGPL-2.1+
#
# Copyright 2017 Zbigniew Jędrzejewski-Szmek
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

systemd_coredump_sources = files('''
        coredump.c
        coredump-vacuum.c
        coredump-vacuum.h
'''.split())

if conf.get('HAVE_ELFUTILS') == 1
        systemd_coredump_sources += files(['stacktrace.c',
                                           'stacktrace.h'])
endif

coredumpctl_sources = files('coredumpctl.c')

install_data('coredump.conf',
             install_dir : pkgsysconfdir)

tests += [
        [['src/coredump/test-coredump-vacuum.c',
          'src/coredump/coredump-vacuum.c',
          'src/coredump/coredump-vacuum.h'],
         [],
         [],
         'ENABLE_COREDUMP', 'manual'],
]
