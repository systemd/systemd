# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [[
        {
                'name' : 'systemd-sulogin-shell',
        },
        daemon_template + {
                'sources' : files('sulogin-shell.c'),
                'dependencies' : [userspace,
                                  versiondep],
        },
]]
