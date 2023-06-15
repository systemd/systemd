# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_BINFMT') != 1
        subdir_done()
endif

executables += [
        libexec_template + {
                'name' : 'systemd-binfmt',
                'public' : true,
                'sources' : files('binfmt.c'),
        },
]

install_emptydir(binfmtdir)
if install_sysconfdir
        install_emptydir(sysconfdir / 'binfmt.d')
endif
