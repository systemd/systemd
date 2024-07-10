# SPDX-License-Identifier: LGPL-2.1+

systemd_bpfstatd_sources = files(
        'bpfstatd-conf.c',
        'bpfstatd-manager.c',
        'bpfstatd.c',
)

bpfstatd_gperf_c = custom_target(
        'bpfstatd-gperf.c',
        input : 'bpfstatd-gperf.gperf',
        output : 'bpfstatd-gperf.c',
        command : [gperf, '@INPUT@', '--output-file', '@OUTPUT@'])

systemd_bpfstatd_sources += [bpfstatd_gperf_c]

executables += [
        libexec_template + {
                'name' : 'systemd-bpfstatd',
                'conditions' : ['ENABLE_BPFSTATD'],
                'sources' : systemd_bpfstatd_sources,
                'include_directories' : includes +
                                        include_directories('.'),
                'dependencies' : [
                        threads,
                ],
        },
        executable_template + {
                'name' : 'bpfstatctl',
                'public' : true,
                'conditions' : ['ENABLE_BPFSTATD'],
                'sources' : files (
                        'bpfstatctl.c',
                ),
                'dependencies' : [
                        threads,
                ],
        },
]

if conf.get('ENABLE_BPFSTATD') == 1
        if install_sysconfdir_samples
                install_data('bpfstatd.conf',
                             install_dir : pkgconfigfiledir)
        endif
endif
