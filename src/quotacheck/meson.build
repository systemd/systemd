# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_QUOTACHECK') != 1
        subdir_done()
endif

executables += [[
        {
                'name' : 'systemd-quotacheck',
        },
        daemon_template + {
                'sources' : files('quotacheck.c'),
        },
]]
