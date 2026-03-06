# SPDX-License-Identifier: LGPL-2.1-or-later

units = [
        { 'file' : 'app.slice' },
        { 'file' : 'background.slice' },
        { 'file' : 'basic.target' },
        { 'file' : 'bluetooth.target' },
        { 'file' : 'capsule@.target' },
        { 'file' : 'default.target' },
        { 'file' : 'exit.target' },
        { 'file' : 'graphical-session-pre.target' },
        { 'file' : 'graphical-session.target' },
        {
          'file' : 'machine.slice',
          'conditions' : ['ENABLE_MACHINED'],
        },
        {
          'file' : 'machines.target',
          'conditions' : ['ENABLE_MACHINED'],
        },
        {
          'file' : 'systemd-machined.service.in',
          'conditions' : ['ENABLE_MACHINED'],
          'symlinks' : ['dbus-org.freedesktop.machine1.service'],
        },
        {
          'file' : 'systemd-machined.socket',
          'conditions' : ['ENABLE_MACHINED'],
          'symlinks' : ['sockets.target.wants/'],
        },
        {
          'file' : 'systemd-importd.service.in',
          'conditions' : ['ENABLE_IMPORTD'],
          'symlinks' : ['dbus-org.freedesktop.import1.service'],
        },
        {
          'file' : 'systemd-importd.socket',
          'conditions' : ['ENABLE_IMPORTD'],
          'symlinks' : ['sockets.target.wants/'],
        },
        {
          'file' : 'systemd-portabled.service.in',
          'conditions' : ['ENABLE_PORTABLED'],
          'symlinks' : ['dbus-org.freedesktop.portable1.service'],
        },
        { 'file' : 'paths.target' },
        { 'file' : 'printer.target' },
        { 'file' : 'session.slice' },
        { 'file' : 'shutdown.target' },
        { 'file' : 'smartcard.target' },
        { 'file' : 'sockets.target' },
        { 'file' : 'sound.target' },
        {
          'file' : 'systemd-ask-password.socket',
          'symlinks' : ['sockets.target.wants/']
        },
        { 'file' : 'systemd-ask-password@.service' },
        { 'file' : 'systemd-exit.service' },
        { 'file' : 'systemd-journalctl@.service' },
        {
          'file' : 'systemd-journalctl.socket',
          'symlinks' : ['sockets.target.wants/'],
        },
        { 'file' : 'systemd-tmpfiles-clean.service' },
        { 'file' : 'systemd-tmpfiles-clean.timer' },
        { 'file' : 'systemd-tmpfiles-setup.service' },
        {
          'file' : 'systemd-nspawn@.service.in',
          'conditions' : ['ENABLE_NSPAWN'],
        },
        {
          'file' : 'systemd-vmspawn@.service.in',
          'conditions' : ['ENABLE_VMSPAWN'],
        },
        { 'file' : 'timers.target' },
        {
          'file' : 'xdg-desktop-autostart.target',
          'conditions': ['ENABLE_XDG_AUTOSTART'],
        }
]

foreach unit : units
        source = unit.get('file')

        if source.endswith('.in')
                needs_jinja = true
                name = source.substring(0, -3)
                assert(name + '.in' == source)
        else
                needs_jinja = false
                name = source
        endif
        source = files(source)

        install = true
        foreach cond : unit.get('conditions', [])
                if conf.get(cond) != 1
                        install = false
                        break
                endif
        endforeach

        if needs_jinja
                t = custom_target(
                        input : source,
                        output : name,
                        command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
                        install : install,
                        install_dir : userunitdir)
        elif install
                install_data(source,
                             install_dir : userunitdir)
        endif

        if install
                foreach target : unit.get('symlinks', [])
                        if target.endswith('/')
                                # '/' is only allowed at the end of the target
                                assert(target.replace('/', '') + '/' == target)
                                install_symlink(name,
                                                pointing_to : '..' / name,
                                                install_dir : userunitdir / target)
                        else
                                install_symlink(target,
                                                pointing_to : name,
                                                install_dir : userunitdir)
                        endif
                endforeach
        endif
endforeach
