# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-tgtmode',
                'conditions' : [
                        'ENABLE_TGTMODE',
                ],
                'sources' : files('tgtmode.c'),
        },
]
