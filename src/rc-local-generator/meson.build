# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        generator_template + {
                'name' : 'systemd-rc-local-generator',
                'sources' : files('rc-local-generator.c'),
                'conditions' : [
                        'HAVE_SYSV_COMPAT',
                        'HAVE_SYSV_RC_LOCAL',
                ],
        },
]
