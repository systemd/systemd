# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-volatile-root',
                'conditions' : ['ENABLE_INITRD'],
                'sources' : files('volatile-root.c'),
        },
]
