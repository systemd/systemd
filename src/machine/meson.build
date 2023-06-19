# SPDX-License-Identifier: LGPL-2.1-or-later

libmachine_core_sources = files(
        'image-dbus.c',
        'machine-dbus.c',
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
        [
                {
                        'name' : 'systemd-machined',
                        'dbus' : true,
                        'conditions' : ['ENABLE_MACHINED'],
                },
                daemon_template + {
                        'sources' : files('machined.c'),
                        'link_with' : [libmachine_core,
                                       libshared],
                },
        ],
        [
                {
                        'name' : 'machinectl',
                        'public' : true,
                        'conditions' : ['ENABLE_MACHINED'],
                },
                executable_template + {
                        'sources' : files('machinectl.c'),
                        'dependencies' : [liblz4,
                                          libxz,
                                          libzstd,
                                          threads,
                                          userspace,
                                          versiondep],
                        'install_dir' : rootbindir,
                },
        ],
]

if conf.get('ENABLE_MACHINED') == 1
        install_data('org.freedesktop.machine1.conf',
                     install_dir : dbuspolicydir)
        install_data('org.freedesktop.machine1.service',
                     install_dir : dbussystemservicedir)
        install_data('org.freedesktop.machine1.policy',
                     install_dir : polkitpolicydir)
endif

tests += [
        {
                'sources' : files('test-machine-tables.c'),
                'link_with': [
                        libmachine_core,
                        libshared
                ],
                'dependencies': threads,
        },
]
