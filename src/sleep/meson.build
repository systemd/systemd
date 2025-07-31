# SPDX-License-Identifier: LGPL-2.1-or-later

sleep_sources = files(
        'sleep.c',
)
sleep_extract_sources = files(
        'battery-capacity.c',
)

executables += [
        libexec_template + {
                'name' : 'systemd-sleep',
                'sources' : sleep_sources + sleep_extract_sources,
                'include_directories' : [libexec_template['include_directories'], include_directories('.')],
                'extract' : sleep_extract_sources,
        },
        test_template + {
                'sources' : files('test-battery-capacity.c'),
                'objects' : ['systemd-sleep'],
        },
]

if install_sysconfdir_samples
        install_data('sleep.conf',
                     install_dir : pkgconfigfiledir)
endif
