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

in_files = ['basic.conf']

enable_sysusers = conf.get('ENABLE_SYSUSERS') == 1

foreach file : in_files
        gen = configure_file(
                input : file + '.in',
                output : file,
                configuration : substs)
        if enable_sysusers
                install_data(gen,
                             install_dir : sysusersdir)
        endif
endforeach

m4_files = ['systemd.conf']

if conf.get('ENABLE_REMOTE') == 1 and conf.get('HAVE_MICROHTTPD') == 1
        m4_files += ['systemd-remote.conf']
endif

foreach file : m4_files
        custom_target(
                'sysusers.d_' + file,
                input : file + '.m4',
                output: file,
                command : [m4, '-P'] + m4_defines + ['@INPUT@'],
                capture : true,
                install : enable_sysusers,
                install_dir : sysusersdir)
endforeach
