# SPDX-License-Identifier: LGPL-2.1-or-later

systemd_coredump_sources = files(
        'coredump.c',
        'coredump-vacuum.c',
)

executables += [
        [
                {
                        'name' : 'systemd-coredump',
                        'conditions' : ['ENABLE_COREDUMP'],
                },
                daemon_template + {
                        'sources' : systemd_coredump_sources,
                        'link_with' : [libshared,
                                       libbasic_compress],
                        'dependencies' : [libacl,
                                          liblz4,
                                          libxz,
                                          libzstd,
                                          threads,
                                          userspace,
                                          versiondep],
                },
        ],
        [
                {
                        'name' : 'coredumpctl',
                        'public' : true,
                        'conditions' : ['ENABLE_COREDUMP'],
                },
                executable_template + {
                        'sources' : files('coredumpctl.c'),
                        'link_with' : [libshared,
                                       libbasic_compress],
                        'dependencies' : [liblz4,
                                          libxz,
                                          libzstd,
                                          threads,
                                          userspace,
                                          versiondep],
                },
        ],
]

if conf.get('ENABLE_COREDUMP') == 1 and install_sysconfdir_samples
        install_data('coredump.conf',
                     install_dir : pkgsysconfdir)
endif

tests += [
        {
                'sources' : files(
                        'test-coredump-vacuum.c',
                        'coredump-vacuum.c',
                ),
                'type' : 'manual',
        },
]
