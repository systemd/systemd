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

meson.add_install_script('sh', '-c',
                         mkdir_p.format(binfmtdir))
if install_sysconfdir
        meson.add_install_script('sh', '-c',
                                 mkdir_p.format(sysconfdir / 'binfmt.d'))
endif
