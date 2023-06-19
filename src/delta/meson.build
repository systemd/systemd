# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [[
        {
                'name' : 'systemd-delta',
                'public' : true,
        },
        executable_template + {
                'sources' : files('delta.c'),
                'dependencies' : [userspace,
                                  versiondep],
        },
]]
