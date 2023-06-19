# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [[
        {
                'name' : 'systemd-id128',
                'public' : true,
        },
        executable_template + {
                'sources' : files('id128.c'),
                'dependencies' : [userspace,
                                  versiondep],
        },
]]
