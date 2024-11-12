# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('HAVE_BLKID') != 1
        subdir_done()
endif

executables += [
        executable_template + {
                'name' : 'systemd-dissect',
                'public' : true,
                'sources' : files('dissect.c'),
        },
]

install_emptydir(sbindir)
meson.add_install_script(sh, '-c',
                         ln_s.format(bindir / 'systemd-dissect',
                                     sbindir / 'mount.ddi'))
