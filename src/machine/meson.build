# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_MACHINED') != 1
        subdir_done()
endif

systemd_machined_sources = files(
        'machined.c'
)
systemd_machined_extract_sources = files(
        'image.c',
        'image-dbus.c',
        'image-varlink.c',
        'machine-dbus.c',
        'machine-varlink.c',
        'machine.c',
        'machined-core.c',
        'machined-dbus.c',
        'machined-varlink.c',
        'operation.c',
)

executables += [
        libexec_template + {
                'name' : 'systemd-machined',
                'dbus' : true,
                'sources' : systemd_machined_sources + systemd_machined_extract_sources,
                'extract' : systemd_machined_extract_sources,
        },
        executable_template + {
                'name' : 'machinectl',
                'public' : true,
                'sources' : files('machinectl.c'),
                'dependencies' : [
                        liblz4_cflags,
                        libxz_cflags,
                        libzstd_cflags,
                        threads,
                ],
        },
        test_template + {
                'sources' : files('test-machine-tables.c'),
                'objects' : ['systemd-machined'],
                'dependencies': threads,
        },
]

install_data('org.freedesktop.machine1.conf',
             install_dir : dbuspolicydir)
install_data('org.freedesktop.machine1.service',
             install_dir : dbussystemservicedir)
install_data('org.freedesktop.machine1.policy',
             install_dir : polkitpolicydir)
