# SPDX-License-Identifier: LGPL-2.1-or-later

systemd_machined_sources = files(
        'machined.c',
        'machined.h',
)

libmachine_core_sources = files(
        'image-dbus.c',
        'image-dbus.h',
        'machine-dbus.c',
        'machine-dbus.h',
        'machine.c',
        'machine.h',
        'machined-core.c',
        'machined-dbus.c',
        'machined-varlink.c',
        'machined-varlink.h',
        'operation.c',
        'operation.h',
)

libmachine_core = static_library(
        'machine-core',
        libmachine_core_sources,
        include_directories : includes,
        dependencies : threads,
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
        [files('test-machine-tables.c'),
         [libmachine_core,
          libshared],
         [threads]],
]
