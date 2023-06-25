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
        libexec_template + {
                'name' : 'systemd-userwork',
                'sources' : files('userwork.c'),
                'dependencies' : dependencies,
        },
        libexec_template + {
                'name' : 'systemd-userdbd',
                'sources' : userdbd_sources,
                'dependencies' : dependencies,
        },
        executable_template + {
                'name' : 'userdbctl',
                'sources' : files('userdbctl.c'),
                'dependencies' : dependencies,
        },
]
