# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [[
        {
                'name' : 'systemd-sleep',
        },
        daemon_template + {
                'sources' : files('sleep.c'),
                'dependencies' : [userspace,
                                  versiondep],
        },
]]

if install_sysconfdir_samples
        install_data('sleep.conf',
                     install_dir : pkgsysconfdir)
endif
