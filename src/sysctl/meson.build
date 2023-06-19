# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [[
        {
                'name' : 'systemd-sysctl',
                'public' : true,
        },
        daemon_template + {
                'sources' : files('sysctl.c'),
                'dependencies' : [userspace,
                                  versiondep],
        },
]]
