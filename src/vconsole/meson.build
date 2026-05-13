# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-vconsole-setup',
                'conditions' : ['ENABLE_VCONSOLE'],
                'sources' : files('vconsole-setup.c'),
        },
]
