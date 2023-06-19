# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_UTMP') != 1
        subdir_done()
endif

executables += [[
        {
                'name' : 'systemd-update-utmp',
        },
        daemon_template + {
                'sources' : files('update-utmp.c'),
                'dependencies' : [libaudit,
                                  userspace,
                                  versiondep],
        },
]]
