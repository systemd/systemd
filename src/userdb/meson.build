# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-userwork',
                'conditions' : ['ENABLE_USERDB'],
                'sources' : files('userwork.c'),
                'dependencies' : threads,
        },
        libexec_template + {
                'name' : 'systemd-userdbd',
                'conditions' : ['ENABLE_USERDB'],
                'sources' : files(
                        'userdbd-manager.c',
                        'userdbd.c',
                ),
                'dependencies' : threads,
        },
        executable_template + {
                'name' : 'userdbctl',
                'conditions' : ['ENABLE_USERDB'],
                'sources' : files('userdbctl.c'),
                'dependencies' : threads,
        },
]
