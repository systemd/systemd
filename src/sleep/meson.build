# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-sleep',
                'sources' : files(
                        'sleep.c',
                        'battery-capacity.c',
                ),
        },
        test_template + {
                'sources' : files(
                        'test-battery-capacity.c',
                        'battery-capacity.c',
                ),
        },
]

if install_sysconfdir_samples
        install_data('sleep.conf',
                     install_dir : pkgconfigfiledir)
endif
