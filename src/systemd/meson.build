# SPDX-License-Identifier: LGPL-2.1-or-later

_systemd_headers = [
        'sd-bus.h',
        'sd-bus-protocol.h',
        'sd-bus-vtable.h',
        'sd-daemon.h',
        'sd-device.h',
        'sd-event.h',
        'sd-gpt.h',
        'sd-hwdb.h',
        'sd-id128.h',
        'sd-journal.h',
        'sd-json.h',
        'sd-login.h',
        'sd-messages.h',
        'sd-path.h',
        'sd-varlink.h',
        'sd-varlink-idl.h',
]

# https://github.com/mesonbuild/meson/issues/1633
systemd_headers = files(_systemd_headers)

_not_installed_headers = [
        'sd-dhcp-client-id.h',
        'sd-dhcp-client.h',
        'sd-dhcp-duid.h',
        'sd-dhcp-lease.h',
        'sd-dhcp-option.h',
        'sd-dhcp-protocol.h',
        'sd-dhcp-server-lease.h',
        'sd-dhcp-server.h',
        'sd-dhcp6-client.h',
        'sd-dhcp6-lease.h',
        'sd-dhcp6-option.h',
        'sd-dhcp6-protocol.h',
        'sd-ipv4acd.h',
        'sd-ipv4ll.h',
        'sd-lldp-rx.h',
        'sd-lldp-tx.h',
        'sd-lldp.h',
        'sd-ndisc.h',
        'sd-ndisc-neighbor.h',
        'sd-ndisc-protocol.h',
        'sd-ndisc-redirect.h',
        'sd-ndisc-router.h',
        'sd-ndisc-router-solicit.h',
        'sd-netlink.h',
        'sd-network.h',
        'sd-radv.h',
        'sd-resolve.h',
]

install_headers(
        systemd_headers,
        '_sd-common.h',
        subdir : 'systemd')

############################################################

if want_tests == 'false'
        subdir_done()
endif

opts = [['c'],
        ['c', '-ansi'],
        ['c', '-std=iso9899:1990'],
        ['c', '-std=iso9899:2011']]

foreach opt : ['-std=iso9899:2017',
               '-std=c23',
              ]
        if cc.has_argument(opt)
                opts += [['c', opt]]
        endif
endforeach

if cxx_cmd != ''
        opts += [['c++'],
                 ['c++', '-std=c++98'],
                 ['c++', '-std=c++11']]

        foreach opt : ['-std=c++14',
                       '-std=c++17',
                       '-std=c++20',
                       '-std=c++23',
                       '-std=c++26',
                      ]
                if cxx.has_argument(opt)
                        opts += [['c++', opt]]
                endif
        endforeach
endif

foreach header : _systemd_headers + _not_installed_headers + [libudev_h_path]
        foreach opt : opts
                std_name = opt.length() == 2 ? '_'.join(opt[1].split(':')) : ''
                test('cc-' + fs.name(header) + '_' + opt[0] + std_name,
                     env,
                     suite : 'headers',
                     args : [cc.cmd_array(),
                             '-c',
                             '-x', opt,
                             '-Wall',
                             '-Wextra',
                             '-Werror',
                             '-pedantic',
                             '-Wno-long-long',
                             '-Wno-variadic-macros',
                             '-include', meson.current_source_dir() / header,
                             '-o/dev/null',
                             '/dev/null'])
        endforeach
endforeach
