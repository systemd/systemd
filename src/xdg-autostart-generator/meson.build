# SPDX-License-Identifier: LGPL-2.1-or-later

systemd_xdg_autostart_generator_sources = files(
        'xdg-autostart-generator.c',
        'xdg-autostart-service.c',
)

executables += [
        [
                {
                        'name' : 'systemd-xdg-autostart-generator',
                },
                generator_template + {
                        'sources' : systemd_xdg_autostart_generator_sources,
                        'install_dir' : usergeneratordir,
                },
        ],
        [
                {
                        'name' : 'systemd-xdg-autostart-condition',
                },
                daemon_template + {
                        'sources' : files('xdg-autostart-condition.c'),
                },
        ],
]

tests += [
        {
                'sources' : files(
                        'test-xdg-autostart.c',
                        'xdg-autostart-service.c',
                ),
        },
]

fuzzers += [
        {
                'sources' : files(
                        'fuzz-xdg-desktop.c',
                        'xdg-autostart-service.c',
                ),
        },
]
