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

systemd_nspawn_sources = files('''
        nspawn-cgroup.c
        nspawn-cgroup.h
        nspawn-def.h
        nspawn-expose-ports.c
        nspawn-expose-ports.h
        nspawn-mount.c
        nspawn-mount.h
        nspawn-network.c
        nspawn-network.h
        nspawn-patch-uid.c
        nspawn-patch-uid.h
        nspawn-register.c
        nspawn-register.h
        nspawn-seccomp.c
        nspawn-seccomp.h
        nspawn-settings.c
        nspawn-settings.h
        nspawn-setuid.c
        nspawn-setuid.h
        nspawn-stub-pid1.c
        nspawn-stub-pid1.h
        nspawn.c
'''.split())

nspawn_gperf_c = custom_target(
        'nspawn-gperf.c',
        input : 'nspawn-gperf.gperf',
        output : 'nspawn-gperf.c',
        command : [gperf, '@INPUT@', '--output-file', '@OUTPUT@'])

systemd_nspawn_sources += [nspawn_gperf_c]

tests += [
        [['src/nspawn/test-patch-uid.c',
          'src/nspawn/nspawn-patch-uid.c',
          'src/nspawn/nspawn-patch-uid.h'],
         [libshared],
         [libacl],
         '', 'manual'],
]
