# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [[
        {
                'name' : 'systemd-machine-id-setup',
        },
        executable_template + {
                'sources' : files('machine-id-setup-main.c'),
                'dependencies' : [userspace,
                                  versiondep],
                'install_dir' : rootbindir,
        },
]]
