# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_COREDUMP') != 1
        subdir_done()
endif

systemd_coredump_sources = files(
        'coredump.c',
        'coredump-backtrace.c',
        'coredump-config.c',
        'coredump-context.c',
        'coredump-kernel-helper.c',
        'coredump-receive.c',
        'coredump-send.c',
        'coredump-submit.c',
)
systemd_coredump_extract_sources = files(
        'coredump-vacuum.c',
)

coredump_gperf_c = custom_target(
        input : 'coredump-gperf.gperf',
        output : 'coredump-gperf.c',
        command : [gperf, '@INPUT@', '--output-file', '@OUTPUT@'])

generated_sources += coredump_gperf_c
systemd_coredump_sources += coredump_gperf_c

common_dependencies = [
        liblz4_cflags,
        libxz_cflags,
        libzstd_cflags,
        threads,
]

executables += [
        libexec_template + {
                'name' : 'systemd-coredump',
                'sources' : systemd_coredump_sources,
                'extract' : systemd_coredump_extract_sources,
                'link_with' : [libshared],
                'dependencies' : common_dependencies,
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
