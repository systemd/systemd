# SPDX-License-Identifier: LGPL-2.1-or-later

libmachine_core_sources = files(
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

libmachine_core = static_library(
        'machine-core',
        libmachine_core_sources,
        include_directories : includes,
        dependencies : [threads,
                        userspace],
        build_by_default : false)

executables += [
        libexec_template + {
                'name' : 'systemd-machined',
                'dbus' : true,
                'conditions' : ['ENABLE_MACHINED'],
                'sources' : files('machined.c'),
                'link_with' : [
                        libmachine_core,
                        libshared,
                ],
        },
        executable_template + {
                'name' : 'machinectl',
                'public' : true,
                'conditions' : ['ENABLE_MACHINED'],
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
                'link_with': [
                        libmachine_core,
                        libshared
                ],
                'dependencies': threads,
        },
]

if conf.get('ENABLE_MACHINED') == 1
        install_data('org.freedesktop.machine1.conf',
                     install_dir : dbuspolicydir)
        install_data('org.freedesktop.machine1.service',
                     install_dir : dbussystemservicedir)
        install_data('org.freedesktop.machine1.policy',
                     install_dir : polkitpolicydir)
endif
