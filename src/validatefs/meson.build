# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-validatefs',
                'conditions' : [
                        'ENABLE_VALIDATEFS',
                ],
                'sources' : files('validatefs.c'),
                'dependencies' : [
                        libblkid_cflags,
                ],
        },
]
