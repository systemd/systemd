# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-binfmt',
                'public' : true,
                'conditions' : ['ENABLE_BINFMT'],
                'sources' : files('binfmt.c'),
        },
]

if conf.get('ENABLE_BINFMT') == 1
        install_emptydir(binfmtdir)
        if install_sysconfdir
                install_emptydir(sysconfdir / 'binfmt.d')
        endif
endif
