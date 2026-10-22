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
                'sources' : files('ptyctl.c'),
        },
]

install_data('io.systemd.PTYBroker.policy',
             install_dir : polkitpolicydir)

# Shells invoked by the broker get their own PAM stack name, but by default it is the same as run0's
if pamconfdir != 'no'
        install_symlink('systemd-ptybroker-shell',
                        pointing_to : 'systemd-run0',
                        install_dir : pamconfdir)
endif
