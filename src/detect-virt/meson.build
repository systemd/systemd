# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [[
        {
                'name' : 'systemd-detect-virt',
                'public' : true,
        },
        executable_template + {
                'sources' : files('detect-virt.c'),
                'dependencies' : [userspace,
                                  versiondep],
        },
]]
