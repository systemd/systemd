# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-factory-reset',
                'sources' : files('factory-reset-tool.c'),
        },
        libexec_template + {
                'name' : 'systemd-efivars-clear',
                'sources' : files('efivars-clear.c'),
                'conditions' : ['ENABLE_BOOTLOADER'],
        },
        generator_template + {
                'name' : 'systemd-factory-reset-generator',
                'sources' : files('factory-reset-generator.c'),
        },
]
