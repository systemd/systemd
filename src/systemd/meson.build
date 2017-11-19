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

_systemd_headers = '''
        sd-bus.h
        sd-bus-protocol.h
        sd-bus-vtable.h
        sd-daemon.h
        sd-event.h
        sd-id128.h
        sd-journal.h
        sd-login.h
        sd-messages.h
'''.split()

# https://github.com/mesonbuild/meson/issues/1633
systemd_headers = files(_systemd_headers)

#  sd-device.h
#  sd-hwdb.h
#  sd-dhcp6-client.h
#  sd-dhcp6-lease.h
#  sd-dhcp-client.h
#  sd-dhcp-lease.h
#  sd-dhcp-server.h
#  sd-ipv4acd.h
#  sd-ipv4ll.h
#  sd-lldp.h
#  sd-ndisc.h
#  sd-netlink.h
#  sd-network.h
#  sd-path.h
#  sd-resolve.h
#  sd-utf8.h

install_headers(
        systemd_headers,
        '_sd-common.h',
        subdir : 'systemd')


############################################################

opts = [['c'],
        ['c', '-ansi'],
        ['c', '-std=iso9899:1990']]

cxx = find_program('c++', required : false)
if cxx.found()
        opts += [['c++']]
endif

foreach header : _systemd_headers
        foreach opt : opts
                name = ''.join([header, ':'] + opt)
                test('cc-' + name,
                     check_compilation_sh,
                     args : cc.cmd_array() + ['-c', '-x'] + opt +
                            ['-Werror', '-include',
                             join_paths(meson.current_source_dir(), header)])
        endforeach
endforeach
