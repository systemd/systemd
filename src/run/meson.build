# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        executable_template + {
                'name' : 'systemd-run',
                'public' : true,
                'sources' : files('run.c'),
        },
]

install_symlink('run0',
                pointing_to : 'systemd-run',
                install_dir : bindir)

custom_target(
        input : 'systemd-run0.in',
        output : 'systemd-run0',
        command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
        install : pamconfdir != 'no',
        install_dir : pamconfdir)
