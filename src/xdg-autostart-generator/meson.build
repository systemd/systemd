# SPDX-License-Identifier: LGPL-2.1-or-later

systemd_xdg_autostart_generator_sources = files(
        'xdg-autostart-generator.c',
        'xdg-autostart-service.c',
)

executables += [
        executable_template + {
                'name' : 'systemd-xdg-autostart-generator',
                'conditions' : ['ENABLE_XDG_AUTOSTART'],
                'sources' : systemd_xdg_autostart_generator_sources,
                'install_dir' : usergeneratordir,
        },
        libexec_template + {
                'name' : 'systemd-xdg-autostart-condition',
                'conditions' : ['ENABLE_XDG_AUTOSTART'],
                'sources' : files('xdg-autostart-condition.c'),
        },
        test_template + {
                'sources' : files(
                        'test-xdg-autostart.c',
                        'xdg-autostart-service.c',
                ),
        },
        fuzz_template + {
                'sources' : files(
                        'fuzz-xdg-desktop.c',
                        'xdg-autostart-service.c',
                ),
        },
]
