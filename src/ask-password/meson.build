# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        executable_template + {
                'name' : 'systemd-ask-password',
                'public' : true,
                'sources' : files('ask-password.c'),
                'arg_parser' : files('ask-password.args'),
        },
]

install_data('io.systemd.ask-password.policy',
             install_dir : polkitpolicydir)
