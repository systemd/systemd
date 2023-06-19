# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [[
        {
                'name' : 'systemd-cgls',
                'public' : true,
        },
        executable_template + {
                'sources' : files('cgls.c'),
                'dependencies' : [userspace,
                                  versiondep],
        },
]]
