# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_XDG_AUTOSTART') != 1
        subdir_done()
endif

systemd_xdg_autostart_generator_sources = files(
        'xdg-autostart-generator.c',
)
systemd_xdg_autostart_generator_extract_sources = files(
        'xdg-autostart-service.c',
)

executables += [
        executable_template + {
                'name' : 'systemd-xdg-autostart-generator',
                'sources' : systemd_xdg_autostart_generator_sources +
                            systemd_xdg_autostart_generator_extract_sources,
                'extract' : systemd_xdg_autostart_generator_extract_sources,
                'install_dir' : usergeneratordir,
        },
        libexec_template + {
                'name' : 'systemd-xdg-autostart-condition',
                'sources' : files('xdg-autostart-condition.c'),
        },
        test_template + {
                'sources' : files('test-xdg-autostart.c'),
                'objects' : ['systemd-xdg-autostart-generator'],
        },
        fuzz_template + {
                'sources' : files('fuzz-xdg-desktop.c'),
                'objects' : ['systemd-xdg-autostart-generator'],
        },
]
