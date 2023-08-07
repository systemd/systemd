# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-update-utmp',
                'conditions' : ['ENABLE_UTMP'],
                'sources' : files('update-utmp.c'),
                'dependencies' : libaudit,
        },
]
