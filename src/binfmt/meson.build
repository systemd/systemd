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
        meson.add_install_script('sh', '-c',
                         mkdir_p.format(binfmtdir))
        if install_sysconfdir
                meson.add_install_script('sh', '-c',
                                         mkdir_p.format(sysconfdir / 'binfmt.d'))
        endif
endif
