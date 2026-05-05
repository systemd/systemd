# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        executable_template + {
                'name' : 'systemd-sysinstall',
                'public' : true,
                'conditions' : ['ENABLE_SYSINSTALL'],
                'sources' : files('sysinstall.c'),
        },
]
