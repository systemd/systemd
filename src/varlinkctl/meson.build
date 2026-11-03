# SPDX-License-Identifier: LGPL-2.1-or-later

varlinkctl_sources = files(
        'varlinkctl.c',
)

executables += [
        executable_template + {
                'name' : 'varlinkctl',
                'sources' : varlinkctl_sources,
                'dependencies' : [
                        libbpf_cflags,
                ],
        },
]

install_emptydir(varlinkbridgesdir)

if conf.get('ENABLE_VARLINK_SFTP') == 1
        install_data('io.systemd.sftp.policy',
                     install_dir : polkitpolicydir)
endif
