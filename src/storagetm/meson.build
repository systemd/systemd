# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-storagetm',
                'conditions' : [
                        'ENABLE_STORAGETM',
                ],
                'sources' : files('storagetm.c'),
        },
]
