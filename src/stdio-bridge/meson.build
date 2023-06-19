# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [[
        {
                'name' : 'systemd-stdio-bridge',
                'public' : true,
        },
        executable_template + {
                'sources' : files('stdio-bridge.c'),
                'dependencies' : [userspace,
                                  versiondep],
        },
]]
