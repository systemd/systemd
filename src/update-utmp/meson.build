# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_UTMP') != 1
        subdir_done()
endif

executables += [
        daemon_template + {
                'name' : 'systemd-update-utmp',
                'sources' : files('update-utmp.c'),
                'dependencies' : [libaudit,
                                  userspace,
                                  versiondep],
        },
]
