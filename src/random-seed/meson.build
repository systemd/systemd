# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_RANDOMSEED') != 1
        subdir_done()
endif

executables += [
        daemon_template + {
                'name' : 'systemd-random-seed',
                'sources' : files('random-seed.c'),
                'dependencies' : [userspace,
                                  versiondep],
        },
]
