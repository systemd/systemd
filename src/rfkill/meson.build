# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_RFKILL') != 1
        subdir_done()
endif

executables += [[
        {
                'name' : 'systemd-rfkill',
        },
        daemon_template + {
                'sources' : files('rfkill.c'),
        },
]]
