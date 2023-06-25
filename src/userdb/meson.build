# SPDX-License-Identifier: LGPL-2.1-or-later

userdbd_sources = files(
        'userdbd-manager.c',
        'userdbd.c',
)

dependencies = [
        threads,
        versiondep,
]

executables += [
        libexec_template + {
                'name' : 'systemd-userwork',
                'conditions' : ['ENABLE_USERDB'],
                'sources' : files('userwork.c'),
                'dependencies' : dependencies,
        },
        libexec_template + {
                'name' : 'systemd-userdbd',
                'conditions' : ['ENABLE_USERDB'],
                'sources' : userdbd_sources,
                'dependencies' : dependencies,
        },
        executable_template + {
                'name' : 'userdbctl',
                'conditions' : ['ENABLE_USERDB'],
                'sources' : files('userdbctl.c'),
                'dependencies' : dependencies,
        },
]
