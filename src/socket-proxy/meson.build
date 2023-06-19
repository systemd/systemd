# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [[
        {
                'name' : 'systemd-socket-proxyd',
                'public' : true,
        },
        daemon_template + {
                'sources' : files('socket-proxyd.c'),
                'dependencies' : [threads,
                                  userspace,
                                  versiondep],
        },
]]
