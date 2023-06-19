# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [[
        {
                'name' : 'systemd-cgtop',
                'public' : true,
        },
        executable_template + {
                'sources' : files('cgtop.c'),
                'dependencies' : [userspace,
                                  versiondep],
        },
]]
