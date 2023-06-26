# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        generator_template + {
                'name' : 'systemd-rc-local-generator',
                'conditions' : ['HAVE_SYSV_COMPAT'],
                'sources' : files('rc-local-generator.c'),
        },
]
