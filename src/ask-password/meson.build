# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [[
        {
                'name' : 'systemd-ask-password',
                'public' : true,
        },
        executable_template + {
                'sources' : files('ask-password.c'),
                'dependencies' : [userspace,
                                  versiondep],
                'install_dir' : rootbindir,
        },
]]
