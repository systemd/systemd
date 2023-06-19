# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [[
        {
                'name' : 'systemd-rc-local-generator',
                'conditions' : ['HAVE_SYSV_COMPAT']
        },
        generator_template + {
                'sources' : files('rc-local-generator.c'),
        },
]]
