# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('HAVE_LIBMOUNT') != 1
        subdir_done()
endif

systemd_shutdown_sources = files(
        'detach-dm.c',
        'detach-loopback.c',
        'detach-md.c',
        'shutdown.c',
)
systemd_shutdown_extract_sources = files(
        'detach-swap.c',
        'umount.c',
)

executables += [
        libexec_template + {
                'name' : 'systemd-shutdown',
                'sources' : systemd_shutdown_sources,
                'extract' : systemd_shutdown_extract_sources,
                'dependencies' : libmount_cflags,
        },
        libexec_template + {
                'name' : 'systemd-shutdown.standalone',
                'sources' : systemd_shutdown_sources + systemd_shutdown_extract_sources,
                'c_args' : '-DSTANDALONE',
                'link_with' : [
                        libc_wrapper_static,
                        libbasic_static,
                        libshared_static,
                        libsystemd_static,
                ],
                'dependencies' : libmount_cflags,
        },
        test_template + {
                'sources' : files('test-umount.c'),
                'objects' : ['systemd-shutdown'],
                'dependencies' : libmount_cflags,
        },
]
