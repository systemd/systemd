# SPDX-License-Identifier: LGPL-2.1-or-later

systemd_shutdown_sources = files(
        'detach-dm.c',
        'detach-loopback.c',
        'detach-md.c',
        'detach-swap.c',
        'shutdown.c',
        'umount.c',
)

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
