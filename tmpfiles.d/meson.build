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

enable_tmpfiles = conf.get('ENABLE_TMPFILES') == 1

tmpfiles = [['home.conf',            ''],
            ['journal-nocow.conf',   ''],
            ['systemd-nologin.conf', ''],
            ['systemd-nspawn.conf',  ''],
            ['tmp.conf',             ''],
            ['x11.conf',             ''],
            ['legacy.conf',          'HAVE_SYSV_COMPAT'],
           ]

foreach pair : tmpfiles
        if not enable_tmpfiles
                # do nothing
        elif pair[1] == '' or conf.get(pair[1]) == 1
                install_data(pair[0], install_dir : tmpfilesdir)
        else
                message('Not installing tmpfiles.d/@0@ because @1@ is @2@'
                        .format(pair[0], pair[1], conf.get(pair[1], 0)))
        endif
endforeach

m4_files = [['etc.conf',             ''],
            ['systemd.conf',         ''],
            ['var.conf',             ''],
           ]

foreach pair : m4_files
        if not enable_tmpfiles
                # do nothing
        elif pair[1] == '' or conf.get(pair[1]) == 1
                custom_target(
                        'tmpfiles.d_' + pair[0],
                         input : pair[0] + '.m4',
                         output: pair[0],
                         command : [m4, '-P'] + m4_defines + ['@INPUT@'],
                         capture : true,
                         install : true,
                         install_dir : tmpfilesdir)
        else
                message('Not installing tmpfiles.d/@0@.m4 because @1@ is @2@'
                        .format(pair[0], pair[1], conf.get(pair[1], 0)))
        endif
endforeach

if enable_tmpfiles
        meson.add_install_script(
                'sh', '-c',
                mkdir_p.format(join_paths(sysconfdir, 'tmpfiles.d')))
endif
