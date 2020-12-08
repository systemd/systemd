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
        units += [ 'xdg-desktop-autostart.target', ]
endif

foreach file : units
        install_data(file,
                     install_dir : userunitdir)
endforeach

in_units = [
        ['machine.slice',                       'ENABLE_MACHINED'],
        ['systemd-machined.service',            'ENABLE_MACHINED',
         'dbus-org.freedesktop.machine1.service'],
        ['systemd-importd.service',             'ENABLE_IMPORTD',
         'dbus-org.freedesktop.import1.service'],
]

foreach tuple : in_units
        file = tuple[0]

        # we do this here because install_data does not accept custom_target output
        conds = tuple[1].split(' ')
        install = ((conds.get(0, '') == '' or conf.get(conds[0]) == 1) and
                   (conds.get(1, '') == '' or conf.get(conds[1]) == 1))

        gen1 = configure_file(
                input : file + '.in',
                output : file + '.tmp',
                configuration : substs)
        gen2 = custom_target(
                'user-' + file,
                input : gen1,
                output : file,
                command : [sed, '/^## /d', '@INPUT@'],
                capture : true,
                install : install,
                install_dir : userunitdir)

        if install and tuple.length() > 2
                foreach target : tuple[2].split()
                        meson.add_install_script('../meson-add-wants.sh', userunitdir, target, file)
                endforeach
        endif
endforeach
