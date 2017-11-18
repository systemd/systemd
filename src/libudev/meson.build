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

libudev_sources = files('''
        libudev-private.h
        libudev-device-internal.h
        libudev.c
        libudev-list.c
        libudev-util.c
        libudev-device.c
        libudev-device-private.c
        libudev-enumerate.c
        libudev-monitor.c
        libudev-queue.c
        libudev-hwdb.c
'''.split())

############################################################

libudev_sym = 'libudev.sym'
libudev_sym_path = '@0@/@1@'.format(meson.current_source_dir(), libudev_sym)
libudev = shared_library(
        'udev',
        libudev_sources,
        version : libudev_version,
        include_directories : includes,
        link_args : ['-shared',
                     '-Wl,--version-script=' + libudev_sym_path],
        link_with : [libbasic,
                     libsystemd_internal],
        dependencies : [threads],
        link_depends : libudev_sym,
        install : true,
        install_dir : rootlibdir)

install_headers('libudev.h')
libudev_h_path = '@0@/libudev.h'.format(meson.current_source_dir())

libudev_pc = configure_file(
        input : 'libudev.pc.in',
        output : 'libudev.pc',
        configuration : substs)
install_data(libudev_pc,
             install_dir : pkgconfiglibdir)
