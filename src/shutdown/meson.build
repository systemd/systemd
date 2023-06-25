# SPDX-License-Identifier: LGPL-2.1-or-later

systemd_shutdown_sources = files(
        'detach-dm.c',
        'detach-loopback.c',
        'detach-md.c',
        'detach-swap.c',
        'shutdown.c',
        'umount.c',
)

executables += [
        libexec_template + {
                'name' : 'systemd-shutdown',
                'sources' : systemd_shutdown_sources,
                'dependencies' : libmount,
        },
        libexec_template + {
                'name' : 'systemd-shutdown.standalone',
                'sources' : systemd_shutdown_sources,
                'c_args' : '-DSTANDALONE',
                'link_with' : [libshared_static,
                               libbasic,
                               libsystemd_static],
                'dependencies' : libmount,
                'build_by_default' : have_standalone_binaries,
                'install' : have_standalone_binaries,
        },
]

tests += [
        {
                'sources' : files(
                        'detach-swap.c',
                        'test-umount.c',
                        'umount.c',
                ),
                'dependencies' : libmount,
        },
]
