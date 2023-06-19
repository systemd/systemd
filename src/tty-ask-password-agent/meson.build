# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [[
        {
                'name' : 'systemd-tty-ask-password-agent',
                'public' : true,
        },
        executable_template + {
                'sources' : files('tty-ask-password-agent.c'),
                'dependencies' : [userspace,
                                  versiondep],
                'install_dir' : rootbindir,
        },
]]
