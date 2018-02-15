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

systemd_machined_sources = files('''
        machined.c
        machined.h
'''.split())

libmachine_core_sources = files('''
        machine.c
        machine.h
        machined-dbus.c
        machine-dbus.c
        machine-dbus.h
        image-dbus.c
        image-dbus.h
        operation.c
        operation.h
'''.split())

libmachine_core = static_library(
        'machine-core',
        libmachine_core_sources,
        include_directories : includes,
        dependencies : [threads])

if conf.get('ENABLE_MACHINED') == 1
        install_data('org.freedesktop.machine1.conf',
                     install_dir : dbuspolicydir)
        install_data('org.freedesktop.machine1.service',
                     install_dir : dbussystemservicedir)

        policy = configure_file(
                input : 'org.freedesktop.machine1.policy.in',
                output : 'org.freedesktop.machine1.policy',
                configuration : substs)
        install_data(policy,
                     install_dir : polkitpolicydir)
endif

tests += [
        [['src/machine/test-machine-tables.c'],
         [libmachine_core,
          libshared],
         [threads],
         'ENABLE_MACHINED'],
]
