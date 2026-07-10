# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('HAVE_LIBMOUNT') != 1
        subdir_done()
endif

shutdown_detach_sources = files(
        'detach-swap.c',
        'umount.c',
)

executables += [
        libexec_template + {
                'name' : 'systemd-shutdown',
                'export' : files(
                        'detach-dm.c',
                        'detach-loopback.c',
                        'detach-md.c',
                        'shutdown.c',
                ) + shutdown_detach_sources,
                'dependencies' : libmount_cflags,
                'install' : have_standalone_binaries ? 'both' : 'yes',
        },
        test_template + {
                'sources' : files('test-umount.c') +
                            shutdown_detach_sources,
                'dependencies' : libmount_cflags,
        },
]
