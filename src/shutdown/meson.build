# SPDX-License-Identifier: LGPL-2.1-or-later

systemd_shutdown_sources = files(
        'detach-dm.c',
        'detach-md.c',
        'shutdown.c',
        'umount.c',
)

tests += [
        {
                'sources' : files(
                        'test-umount.c',
                        'umount.c',
                ),
                'dependencies' : libmount,
        },
]
