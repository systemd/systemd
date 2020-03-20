# SPDX-License-Identifier: LGPL-2.1+

units = [
        'basic.target',
        'bluetooth.target',
        'default.target',
        'exit.target',
        'graphical-session-pre.target',
        'graphical-session.target',
        'paths.target',
        'printer.target',
        'shutdown.target',
        'smartcard.target',
        'sockets.target',
        'sound.target',
        'systemd-exit.service',
        'systemd-tmpfiles-clean.service',
        'systemd-tmpfiles-clean.timer',
        'systemd-tmpfiles-setup.service',
        'timers.target',
        'wayland-session-pre.target',
        'wayland-session.target',
        'x11-session-pre.target',
        'x11-session.target',
]

foreach file : units
        install_data(file,
                     install_dir : userunitdir)
endforeach
