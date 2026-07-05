# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_VARLINK_MONITORD') != 1
        subdir_done()
endif

systemd_varlink_monitord_sources = files(
        'varlink-monitord.c',
        'ringbuf.c',
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

systemd_varlink_monitorctl_sources = files(
        'varlink-monitorctl.c',
        'ringbuf.c',
)

executables += [
        executable_template + {
                'name' : 'varlink-monitorctl',
                'public' : true,
                'sources' : systemd_varlink_monitorctl_sources,
        },
]

install_data('io.systemd.VarlinkMonitor.policy',
             install_dir : polkitpolicydir)
