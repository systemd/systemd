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
        meson.add_install_script('sh', '-c',
                                 mkdir_p.format(modulesloaddir))
        if install_sysconfdir
                meson.add_install_script('sh', '-c',
                                         mkdir_p.format(sysconfdir / 'modules-load.d'))
        endif
endif
