# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        executable_template + {
                'name' : 'systemd-manifest',
                'sources' : files(
                        'manifest.c',
                        'manifest-join.c',
                ),
                'dependencies' : libopenssl_cflags,
        },
]
