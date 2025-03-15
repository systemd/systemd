# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-validatefs',
                'conditions' : [
                        'HAVE_BLKID',
                ],
                'sources' : files('validatefs.c'),
                'dependencies' : [
                        libblkid,
                ],
        },
]
