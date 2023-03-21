# SPDX-License-Identifier: LGPL-2.1-or-later

systemd_machined_sources = files(
        'machined.c',
)

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
