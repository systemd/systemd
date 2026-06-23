# SPDX-License-Identifier: LGPL-2.1-or-later

shutdown_detach_sources = files(
        'detach-swap.c',
        'umount.c',
)

systemd_shutdown_sources = files(
        'detach-dm.c',
        'detach-loopback.c',
        'detach-md.c',
        'shutdown.c',
)

if conf.get('HAVE_LIBMOUNT') == 1
        systemd_shutdown_sources += shutdown_detach_sources
endif

executables += [
        libexec_template + {
                'name' : 'systemd-shutdown',
                'extract' : systemd_shutdown_sources,
                'dependencies' : libmount_cflags,
        },
        libexec_template + {
                'name' : 'systemd-shutdown.standalone',
                'objects' : ['systemd-shutdown'],
                'link_with' : [
                        libc_wrapper_static,
                        libbasic_static,
                        libshared_static,
                        libsystemd_static,
                ],
                'dependencies' : libmount_cflags,
        },
        test_template + {
                'sources' : files('test-umount.c') +
                            shutdown_detach_sources,
                'dependencies' : libmount_cflags,
                'conditions' : ['HAVE_LIBMOUNT'],
        },
]
