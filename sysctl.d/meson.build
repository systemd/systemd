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

install_data(
        '50-default.conf',
        install_dir : sysctldir)

in_files = []

if conf.get('ENABLE_COREDUMP') == 1
        in_files += ['50-coredump.conf']
endif

foreach file : in_files
        gen = configure_file(
                input : file + '.in',
                output : file,
                configuration : substs)
        install_data(gen,
                     install_dir : sysctldir)
endforeach

meson.add_install_script('sh', '-c',
                         mkdir_p.format(join_paths(sysconfdir, 'sysctl.d')))
