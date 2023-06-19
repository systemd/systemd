# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('HAVE_SYSV_COMPAT') != 1
        subdir_done()
endif

executables += [[
        {
                'name' : 'systemd-initctl',
        },
        daemon_template + {
                'sources' : files('initctl.c'),
        },
]]
