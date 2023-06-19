# SPDX-License-Identifier: LGPL-2.1-or-later

systemd_xdg_autostart_generator_sources = files(
        'xdg-autostart-generator.c',
        'xdg-autostart-service.c',
)

executables += [
        executable_template + {
                'name' : 'systemd-xdg-autostart-generator',
                'sources' : systemd_xdg_autostart_generator_sources,
                'install_dir' : usergeneratordir,
        },
        daemon_template + {
                'name' : 'systemd-xdg-autostart-condition',
                'sources' : files('xdg-autostart-condition.c'),
        },
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
