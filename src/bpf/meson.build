# SPDX-License-Identifier: LGPL-2.1+

systemd_bpfd_sources = files(
        'bpfd-manager.c',
        'bpfd.c',
)

executables += [
        libexec_template + {
                'name' : 'systemd-bpfd',
                'conditions' : ['ENABLE_BPFD'],
                'sources' : systemd_bpfd_sources,
                'dependencies' : [
                        threads,
                ],
        },
        executable_template + {
                'name' : 'bpfctl',
                'public' : true,
                'conditions' : ['ENABLE_BPFD'],
                'sources' : files (
                        'bpfctl.c',
                ),
                'dependencies' : [
                        threads,
                ],
        },
]
