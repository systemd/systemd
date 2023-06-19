# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [[
        {
                'name' : 'systemd-ac-power',
                'public' : true,
        },
        executable_template + {
                'sources' : files('ac-power.c'),
                'dependencies' : [userspace,
                                  versiondep],
        },
]]
