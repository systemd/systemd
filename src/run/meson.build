# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        executable_template + {
                'name' : 'systemd-run',
                'public' : true,
                'sources' : files('run.c'),
        },
]

install_emptydir(bindir)

meson.add_install_script(sh, '-c',
                             ln_s.format(bindir / 'systemd-run',
                                         bindir / 'run0'))

custom_target(
        'systemd-run0',
        input : 'systemd-run0.in',
        output : 'systemd-run0',
        command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
        install : pamconfdir != 'no',
        install_dir : pamconfdir)
