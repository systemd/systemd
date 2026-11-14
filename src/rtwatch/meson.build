# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_RTWATCH') != 1
        subdir_done()
endif

executables += [
        libexec_template + {
                'name' : 'systemd-rtwatchd',
                'dbus' : true,
                'sources' : files(
                        'rtwatchd.c',
                        'rtwatchd-dbus.c',
                        'rtwatchd-manager.c',
                        'rtwatchd-varlink.c',
                ),
                'export' : files('threadref.c'),
        },
        test_template + {
                'sources' : files('test-threadref.c'),
                'import' : ['systemd-rtwatchd'],
        },
        executable_template + {
                'name' : 'systemd-rtwatch',
                'sources' : files('rtwatch-tool.c'),
                'import' : ['systemd-rtwatchd'],
        },
]

install_data('org.freedesktop.RealtimeKit1.conf',
             install_dir : dbuspolicydir)
install_data('org.freedesktop.RealtimeKit1.service',
             install_dir : dbussystemservicedir)
install_data('org.freedesktop.RealtimeKit1.policy',
             install_dir : polkitpolicydir)

if install_sysconfdir_samples
        install_data('rtwatchd.conf',
                     install_dir : pkgconfigfiledir)
endif
