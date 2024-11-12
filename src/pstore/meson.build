# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_PSTORE') != 1
        subdir_done()
endif

executables += [
        libexec_template + {
                'name' : 'systemd-pstore',
                'sources' : files('pstore.c'),
                'dependencies' : [
                        libacl,
                        liblz4_cflags,
                        libxz_cflags,
                        libzstd_cflags,
                        threads,
                ],
        },
]

if install_sysconfdir_samples
        install_data('pstore.conf',
                     install_dir : pkgconfigfiledir)
endif
