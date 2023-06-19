# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [[
        {
                'name' : 'systemd-user-sessions',
                'conditions' : ['HAVE_PAM'],
        },
        daemon_template + {
                'sources' : files('user-sessions.c'),
        },
]]
