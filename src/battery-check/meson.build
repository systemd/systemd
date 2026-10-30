# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-battery-check',
                'conditions' : ['ENABLE_BATTERY_CHECK'],
                'sources' : files('battery-check.c'),
        },
]
