# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-ptybrokerd',
                'sources' : files(
                        'ptybroker.c',
                        'ptybroker-monitor.c',
                        'ptybroker-pty.c',
                        'ptybroker-util.c',
                ),
        },
        executable_template + {
                'name' : 'ptyctl',
                'public' : true,
                'sources' : files('ptyctl.c'),
        },
]

install_data('io.systemd.PTYBroker.policy',
             install_dir : polkitpolicydir)
