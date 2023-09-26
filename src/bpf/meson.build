# SPDX-License-Identifier: LGPL-2.1+

systemd_bpfd_sources = files(
        'bpfd-conf.c',
        'bpfd-manager.c',
        'bpfd.c',
)

bpfd_gperf_c = custom_target(
        'bpfd-gperf.c',
        input : 'bpfd-gperf.gperf',
        output : 'bpfd-gperf.c',
        command : [gperf, '@INPUT@', '--output-file', '@OUTPUT@'])

systemd_bpfd_sources += [bpfd_gperf_c]

executables += [
        libexec_template + {
                'name' : 'systemd-bpfd',
                'conditions' : ['ENABLE_BPFD'],
                'sources' : systemd_bpfd_sources,
                'include_directories' : includes +
                                        include_directories('.'),
                'dependencies' : [
                        threads,
                ],
        },
]

if conf.get('ENABLE_BPFD') == 1
        if install_sysconfdir_samples
                install_data('bpfd.conf',
                             install_dir : pkgconfigfiledir)
        endif
endif
