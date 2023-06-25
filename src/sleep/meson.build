# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-sleep',
                'sources' : files('sleep.c'),
                'dependencies' : [userspace,
                                  versiondep],
        },
]

if install_sysconfdir_samples
        install_data('sleep.conf',
                     install_dir : pkgsysconfdir)
endif
