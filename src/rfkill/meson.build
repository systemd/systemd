# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-rfkill',
                'conditions' : ['ENABLE_RFKILL'],
                'sources' : files('rfkill.c'),
        },
]
