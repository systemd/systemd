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

systemd_timesyncd_sources = files('''
        timesyncd.c
        timesyncd-manager.c
        timesyncd-manager.h
        timesyncd-conf.c
        timesyncd-conf.h
        timesyncd-server.c
        timesyncd-server.h
'''.split())

timesyncd_gperf_c = custom_target(
        'timesyncd-gperf.c',
        input : 'timesyncd-gperf.gperf',
        output : 'timesyncd-gperf.c',
        command : [gperf, '@INPUT@', '--output-file', '@OUTPUT@'])

systemd_timesyncd_sources += [timesyncd_gperf_c]

if conf.get('ENABLE_TIMESYNCD') == 1
        timesyncd_conf = configure_file(
                input : 'timesyncd.conf.in',
                output : 'timesyncd.conf',
                configuration : substs)
        install_data(timesyncd_conf,
                     install_dir : pkgsysconfdir)
endif

############################################################

tests += [
        [['src/timesync/test-timesync.c',
          'src/timesync/timesyncd-manager.c',
          'src/timesync/timesyncd-manager.h',
          'src/timesync/timesyncd-conf.c',
          'src/timesync/timesyncd-conf.h',
          'src/timesync/timesyncd-server.c',
          'src/timesync/timesyncd-server.h',
          timesyncd_gperf_c],
         [libshared],
         [libm],
         'ENABLE_TIMESYNCD'],
]
