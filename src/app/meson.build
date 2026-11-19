# SPDX-License-Identifier: LGPL-2.1-or-later

appd_sources = files(
        'appd-instance.c',
        'appd-instance-varlink.c',
        'appd-manager.c',
)

executables += [
        libexec_template + {
                'name' : 'systemd-appd',
                'conditions' : [
                        'ENABLE_APPD'
                ],
                'sources' : appd_sources,
        },
]
