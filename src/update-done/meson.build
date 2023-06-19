# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [[
        {
                'name' : 'systemd-update-done',
        },
        daemon_template + {
                'sources' : files('update-done.c'),
                'dependencies' : [userspace,
                                  versiondep],
        },
]]
