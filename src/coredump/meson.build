# SPDX-License-Identifier: LGPL-2.1-or-later

systemd_coredump_sources = files(
        'coredump.c',
        'coredump-vacuum.c',
)

common_link_with = [
        libshared,
        libbasic_compress,
]

common_dependencies = [
        liblz4,
        libxz,
        libzstd,
        threads,
]

executables += [
        libexec_template + {
                'name' : 'systemd-coredump',
                'conditions' : ['ENABLE_COREDUMP'],
                'sources' : systemd_coredump_sources,
                'link_with' : common_link_with,
                'dependencies' : common_dependencies + [libacl],
        },
        executable_template + {
                'name' : 'coredumpctl',
                'public' : true,
                'conditions' : ['ENABLE_COREDUMP'],
                'sources' : files('coredumpctl.c'),
                'link_with' : common_link_with,
                'dependencies' : common_dependencies,
        },
        test_template + {
                'sources' : files(
                        'test-coredump-vacuum.c',
                        'coredump-vacuum.c',
                ),
                'type' : 'manual',
        },
]

if conf.get('ENABLE_COREDUMP') == 1 and install_sysconfdir_samples
        install_data('coredump.conf',
                     install_dir : pkgconfigfiledir)
endif
