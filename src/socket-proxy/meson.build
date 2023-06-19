# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        daemon_template + {
                'name' : 'systemd-socket-proxyd',
                'public' : true,
                'sources' : files('socket-proxyd.c'),
                'dependencies' : [threads,
                                  userspace,
                                  versiondep],
        },
]
