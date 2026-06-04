# SPDX-License-Identifier: LGPL-2.1-or-later

_systemd_headers = [
        'sd-bus.h',
        'sd-bus-protocol.h',
        'sd-bus-vtable.h',
        'sd-daemon.h',
        'sd-device.h',
        'sd-dlopen.h',
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
        'sd-dhcp-protocol.h',
        'sd-dhcp-relay.h',
        'sd-dhcp-server-lease.h',
        'sd-dhcp-server.h',
        'sd-dhcp6-client.h',
        'sd-dhcp6-lease.h',
        'sd-dhcp6-option.h',
        'sd-dhcp6-protocol.h',
        'sd-dns-resolver.h',
        'sd-future.h',
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

sources += systemd_headers
sources += files(_not_installed_headers)

install_headers(
        systemd_headers,
        '_sd-common.h',
        subdir : 'systemd')

############################################################

if want_tests == 'false'
        subdir_done()
endif

# An empty string means "the compiler default", i.e. no explicit standard flag.
c_stds = ['',
          '-ansi',
          '-std=iso9899:1990', # C90
          '-std=iso9899:1999', # C99
          '-std=iso9899:2011'] # C11

foreach std : ['-std=iso9899:2018', # C17
               '-std=iso9899:2024', # C23
              ]
        if cc.has_argument(std)
                c_stds += std
        endif
endforeach

cxx_stds = []
if cxx_cmd != ''
        cxx_stds += ['',
                     '-std=c++98',
                     '-std=c++11']

        foreach std : ['-std=c++14',
                       '-std=c++17',
                       '-std=c++20',
                       '-std=c++23',
                       '-std=c++26',
                      ]
                if cxx.has_argument(std)
                        cxx_stds += std
                endif
        endforeach
endif

# Run all the (header, language, standard) checks in a single test instead of generating one
# meson test per combination, of which there are hundreds.
header_check_args = []
foreach arg : cc.cmd_array()
        header_check_args += '--cc=' + arg
endforeach
if cxx_cmd != ''
        foreach arg : cxx.cmd_array()
                header_check_args += '--cxx=' + arg
        endforeach
endif
foreach std : c_stds
        header_check_args += '--c-std=' + std
endforeach
foreach std : cxx_stds
        header_check_args += '--cxx-std=' + std
endforeach
foreach arg : ['-Wall',
               '-Wextra',
               '-Werror',
               '-pedantic',
               '-Wno-long-long',
               '-Wno-variadic-macros',
              ]
        header_check_args += '--common-arg=' + arg
endforeach
foreach header : _systemd_headers + _not_installed_headers + [libudev_h_path]
        header_check_args += meson.current_source_dir() / header
endforeach

test('cc-headers',
     files('test-compile-headers.py'),
     suite : 'headers',
     args : header_check_args,
     timeout : 360)
