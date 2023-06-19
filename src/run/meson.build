# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [[
        {
                'name' : 'systemd-run',
                'public' : true,
        },
        executable_template + {
                'sources' : files('run.c'),
                'dependencies' : [userspace,
                                  versiondep],
        },
]]
