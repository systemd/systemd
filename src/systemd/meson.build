# SPDX-License-Identifier: LGPL-2.1+

_systemd_headers = '''
        sd-bus.h
        sd-bus-protocol.h
        sd-bus-vtable.h
        sd-daemon.h
        sd-device.h
        sd-event.h
        sd-hwdb.h
        sd-id128.h
        sd-journal.h
        sd-login.h
        sd-messages.h
'''.split()

# https://github.com/mesonbuild/meson/issues/1633
systemd_headers = files(_systemd_headers)

_not_installed_headers = '''
        sd-dhcp6-client.h
        sd-dhcp6-lease.h
        sd-dhcp-client.h
        sd-dhcp-lease.h
        sd-dhcp-server.h
        sd-ipv4acd.h
        sd-ipv4ll.h
        sd-lldp.h
        sd-ndisc.h
        sd-netlink.h
        sd-network.h
        sd-path.h
        sd-radv.h
        sd-utf8.h
'''.split()

# The following headers do not pass tests.
#  sd-resolve.h

install_headers(
        systemd_headers,
        '_sd-common.h',
        subdir : 'systemd')


############################################################

opts = [['c'],
        ['c', '-ansi'],
        ['c', '-std=iso9899:1990'],
        ['c', '-std=iso9899:2011']]

if cc.has_argument('-std=iso9899:2017')
        opts += [['c', '-std=iso9899:2017']]
endif

cxx = find_program('c++', required : false)
if cxx.found()
        opts += [['c++'],
                 ['c++', '-std=c++98'],
                 ['c++', '-std=c++11']]
        if cc.has_argument('-std=c++14')
                opts += [['c++', '-std=c++14']]
        endif
        if cc.has_argument('-std=c++17')
                opts += [['c++', '-std=c++17']]
        endif
endif

foreach header : _systemd_headers + _not_installed_headers
        foreach opt : opts
                name = ''.join([header, ':'] + opt)
                if want_tests != 'false'
                        test('cc-' + name,
                             check_compilation_sh,
                             args : cc.cmd_array() + ['-c', '-x'] + opt +
                                    ['-Werror', '-include',
                                     join_paths(meson.current_source_dir(), header)])
                endif
        endforeach
endforeach
