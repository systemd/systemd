# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [[
        {
                'name' : 'systemd-remount-fs',
        },
        daemon_template + {
                'sources' : files('remount-fs.c'),
                'dependencies' : [userspace,
                                  versiondep],
        },
]]
