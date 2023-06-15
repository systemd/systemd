# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        executable_template + {
                'name' : 'systemd-dissect',
                'public' : true,
                'conditions' : ['HAVE_BLKID'],
                'sources' : files('dissect.c'),
        },
]

if conf.get('HAVE_BLKID') == 1
        install_symlink('mount.ddi',
                        pointing_to : sbin_to_bin + 'systemd-dissect',
                        install_dir : sbindir)
endif
