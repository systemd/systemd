# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [[
        {
                'name' : 'systemd-fsck',
        },
        daemon_template + {
                'sources' : files('fsck.c'),
                'dependencies' : [userspace,
                                  versiondep],
        },
]]
