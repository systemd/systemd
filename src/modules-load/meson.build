# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('HAVE_KMOD') != 1
        subdir_done()
endif

executables += [
        libexec_template + {
                'name' : 'systemd-modules-load',
                'sources' : files('modules-load.c'),
                'dependencies' : libkmod_cflags,
        },
]

install_emptydir(modulesloaddir)
if install_sysconfdir
        install_emptydir(sysconfdir / 'modules-load.d')
endif
