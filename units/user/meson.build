# SPDX-License-Identifier: LGPL-2.1-or-later

units = [
        'app.slice',
        'background.slice',
        'basic.target',
        'bluetooth.target',
        'default.target',
        'exit.target',
        'graphical-session-pre.target',
        'graphical-session.target',
        'paths.target',
        'printer.target',
        'session.slice',
        'shutdown.target',
        'smartcard.target',
        'sockets.target',
        'sound.target',
        'systemd-exit.service',
        'systemd-tmpfiles-clean.service',
        'systemd-tmpfiles-clean.timer',
        'systemd-tmpfiles-setup.service',
        'timers.target',
]

if conf.get('ENABLE_XDG_AUTOSTART') == 1
        units += 'xdg-desktop-autostart.target'
endif

if conf.get('ENABLE_HOMED') == 1
        units += 'systemd-homed-sync-bulk.service.in'
        units += 'systemd-homed-sync-bulk.path'
endif

foreach file : units
        if file.endswith('.in')
                name = file.substring(0, -3)
                assert(name + '.in' == file)
                custom_target(
                        name,
                        input : file,
                        output : name,
                        command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
                        install_dir : userunitdir)
        else
                install_data(file,
                             install_dir : userunitdir)
        endif
endforeach
