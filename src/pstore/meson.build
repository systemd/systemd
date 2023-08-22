# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-pstore',
                'conditions' : ['ENABLE_PSTORE'],
                'sources' : files('pstore.c'),
                'dependencies' : [
                        libacl,
                        liblz4,
                        libxz,
                        libzstd,
                        threads,
                ],
        },
]

if conf.get('ENABLE_PSTORE') == 1 and install_sysconfdir_samples
        install_data('pstore.conf',
                     install_dir : pkgconfigfiledir)
endif
