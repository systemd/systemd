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
        'timers.target',
        'systemd-exit.service',
        'systemd-tmpfiles-clean.timer',
]

foreach file : units
        install_data(file,
                     install_dir : userunitdir)
endforeach

in_units = [
        'systemd-tmpfiles-clean.service',
        'systemd-tmpfiles-setup.service',
]

foreach file : in_units
        gen = configure_file(
                input : file + '.in',
                output : file,
                configuration : substs)
        install_data(gen,
                     install_dir : userunitdir)
endforeach
