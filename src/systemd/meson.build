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
