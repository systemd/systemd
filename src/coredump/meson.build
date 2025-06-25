# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_COREDUMP') != 1
        subdir_done()
endif

systemd_coredump_sources = files(
        'coredump.c',
)
systemd_coredump_extract_sources = files(
        'coredump-vacuum.c',
)

common_dependencies = [
        liblz4_cflags,
        libxz_cflags,
        libzstd_cflags,
        threads,
]

executables += [
        libexec_template + {
                'name' : 'systemd-coredump',
                'sources' : systemd_coredump_sources + systemd_coredump_extract_sources,
                'extract' : systemd_coredump_extract_sources,
                'link_with' : [libshared],
                'dependencies' : common_dependencies + [libacl],
        },
        executable_template + {
                'name' : 'coredumpctl',
                'public' : true,
                'sources' : files('coredumpctl.c'),
                'link_with' : [libshared],
                'dependencies' : common_dependencies,
        },
        test_template + {
                'sources' : files('test-coredump-vacuum.c'),
                'objects' : ['systemd-coredump'],
                'type' : 'manual',
        },
]

if install_sysconfdir_samples
        install_data('coredump.conf',
                     install_dir : pkgconfigfiledir)
endif
