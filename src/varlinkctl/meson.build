# SPDX-License-Identifier: LGPL-2.1-or-later

varlinkctl_sources = files(
        'varlinkctl.c',
)

executables += [
        executable_template + {
                'name' : 'varlinkctl',
                'public' : true,
                'sources' : varlinkctl_sources,
                'dependencies' : [
                        libbpf_cflags,
                ],
        },
]

install_emptydir(varlinkbridgesdir)
