# SPDX-License-Identifier: LGPL-2.1-or-later

systemd_xdg_autostart_generator_sources = files(
        'xdg-autostart-generator.c',
        'xdg-autostart-service.c',
        'xdg-autostart-service.h')

tests += [
        [files('test-xdg-autostart.c',
               'xdg-autostart-service.c',
               'xdg-autostart-service.h')],
]

fuzzers += [
        [['src/xdg-autostart-generator/fuzz-xdg-desktop.c',
          'src/xdg-autostart-generator/xdg-autostart-service.c',
          'src/xdg-autostart-generator/xdg-autostart-service.h']],
]
