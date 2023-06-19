# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_BACKLIGHT') != 1
        subdir_done()
endif

executables += [[
        {
                'name' : 'systemd-backlight',
        },
        daemon_template + {
                'sources' : files('backlight.c'),
        },
]]
