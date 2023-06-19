# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [[
        {
                'name' : 'systemd-sysv-generator',
                'conditions' : ['HAVE_SYSV_COMPAT']
        },
        generator_template + {
                'sources' : files('sysv-generator.c'),
        },
]]
