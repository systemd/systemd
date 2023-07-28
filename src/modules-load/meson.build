# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-modules-load',
                'conditions' : ['HAVE_KMOD'],
                'sources' : files('modules-load.c'),
                'dependencies' : libkmod,
        },
]

if conf.get('HAVE_KMOD') == 1
        install_emptydir(modulesloaddir)
        if install_sysconfdir
                install_emptydir(sysconfdir / 'modules-load.d')
        endif
endif
