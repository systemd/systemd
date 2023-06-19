# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_RANDOMSEED') != 1
        subdir_done()
endif

executables += [[
        {
                'name' : 'systemd-random-seed',
        },
        daemon_template + {
                'sources' : files('random-seed.c'),
                'dependencies' : [userspace,
                                  versiondep],
        },
]]
