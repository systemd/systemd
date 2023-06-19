# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_USERDB') != 1
        subdir_done()
endif

userdbd_sources = files(
        'userdbd-manager.c',
        'userdbd.c',
)

dependencies = [
        threads,
        userspace,
        versiondep,
]

executables += [
        [
                {
                        'name' : 'systemd-userwork',
                },
                daemon_template + {
                        'sources' : files('userwork.c'),
                        'dependencies' : dependencies,
                },
        ],
        [
                {
                        'name' : 'systemd-userdbd',
                },
                daemon_template + {
                        'sources' : userdbd_sources,
                        'dependencies' : dependencies,
                },
        ],
        [
                {
                        'name' : 'userdbctl',
                },
                executable_template + {
                        'sources' : files('userdbctl.c'),
                        'dependencies' : dependencies,
                },
        ],
]
