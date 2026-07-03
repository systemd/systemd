# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-growfs',
                'sources' : files('growfs.c'),
                'dependencies' : [
                        libcryptsetup_cflags,
                ],
        },
        libexec_template + {
                'name' : 'systemd-makefs',
                'sources' : files('makefs.c'),
        },
]
