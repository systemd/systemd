# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [[
        {
                'name' : 'systemd-path',
                'public' : true,
        },
        executable_template + {
                'sources' : files('path.c'),
                'dependencies' : [userspace,
                                  versiondep],
        },
]]
