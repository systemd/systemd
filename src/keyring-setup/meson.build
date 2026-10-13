# SPDX-License-Identifier: LGPL-2.1-or-later

rust_executables += [
        {
                'name' : 'systemd-keyring-setup',
                'sources' : files('keyring-setup.rs'),
                'install_dir' : libexecdir,
                'conditions' : ['HAVE_OPENSSL'],
        },
]
