# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [[
        {
                'name' : 'systemd-socket-activate',
                'public' : true,
        },
        executable_template + {
                'sources' : files('socket-activate.c'),
                'dependencies' : [threads,
                                  userspace,
                                  versiondep],
        },
]]
