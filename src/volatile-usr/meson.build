# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-volatile-usr',
                'conditions' : ['ENABLE_INITRD'],
                'sources' : files('volatile-usr.c'),
        },
]
