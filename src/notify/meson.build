# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [[
        {
                'name' : 'systemd-notify',
                'public' : true,
        },
        executable_template + {
                'sources' : files('notify.c'),
                'dependencies' : [userspace,
                                  versiondep],
                'install_dir' : rootbindir,
        },
]]
