# SPDX-License-Identifier: LGPL-2.1-or-later

libsleep_core_sources = files(
        'battery-capacity.c',
        'hibernate-util.c',
        'sleep-config.c',
)

libsleep_core = static_library(
        'sleep-core',
        libsleep_core_sources,
        include_directories : includes,
        dependencies : userspace,
        build_by_default : false)

sleep_includes = [includes, include_directories('.')]

sleep_test_template = test_template + {
        'link_with' : [
                libsleep_core,
                libshared,
        ],
}

executables += [
        libexec_template + {
                'name' : 'systemd-sleep',
                'sources' : files(
                        'sleep.c',
                        'battery-capacity.c',
                ),
                'link_with' : [
                        libsleep_core,
                        libshared,
                ],
        },
        sleep_test_template + {
                'sources' : files('test-sleep-config.c'),
        },
        sleep_test_template + {
                'sources' : files('test-fiemap.c'),
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
                     install_dir : pkgsysconfdir)
endif
