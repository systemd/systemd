# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_VCONSOLE') != 1
        subdir_done()
endif

executables += [[
        {
                'name' : 'systemd-vconsole-setup',
        },
        daemon_template + {
                'sources' : files('vconsole-setup.c'),
        },
]]
