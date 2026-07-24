# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_VARLINK_MONITORD') != 1
        subdir_done()
endif

systemd_varlink_monitord_sources = files(
        'varlink-monitord.c',
)

executables += [
        libexec_template + {
                'name' : 'systemd-varlink-monitord',
                'sources' : systemd_varlink_monitord_sources,
                'dependencies' : [
                        libbpf_cflags,
                ],
                'bpf_programs': ['monitor-varlink'],
        },
]

install_data('io.systemd.VarlinkMonitor.policy',
             install_dir : polkitpolicydir)
