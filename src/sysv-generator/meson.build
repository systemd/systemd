# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        generator_template + {
                'name' : 'systemd-sysv-generator',
                'conditions' : ['HAVE_SYSV_COMPAT'],
                'sources' : files('sysv-generator.c'),
        },
]
