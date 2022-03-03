# SPDX-License-Identifier: LGPL-2.1-or-later

systemd_shutdown_sources = files(
        'shutdown.c',
        'umount.c',
        'umount.h',
)

tests += [
        [files('test-umount.c',
               'umount.c',
               'umount.h'),
         [],
         [libmount]],
]
