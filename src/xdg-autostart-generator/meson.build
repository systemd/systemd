# SPDX-License-Identifier: LGPL-2.1-or-later

systemd_xdg_autostart_generator_sources = files(
        'xdg-autostart-generator.c',
        'xdg-autostart-service.c',
)

tests += [
        [files('test-xdg-autostart.c',
               'xdg-autostart-service.c')],
]

fuzzers += [
        [files('fuzz-xdg-desktop.c',
               'xdg-autostart-service.c')],
]
