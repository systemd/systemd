# SPDX-License-Identifier: LGPL-2.1-or-later

systemd_mntwork_sources = files(
        'mntwork.c',
)

systemd_mntfsd_sources = files(
        'mntfsd.c',
        'mntfsd-manager.c',
)

executables += [
        libexec_template + {
                'name' : 'systemd-mntfsd',
                'conditions' : ['ENABLE_MNTFSD'],
                'sources' : systemd_mntfsd_sources,
        },
        libexec_template + {
                'name' : 'systemd-mntwork',
                'conditions' : ['ENABLE_MNTFSD'],
                'sources' : systemd_mntwork_sources,
                'link_with' : common_libs,
                'dependencies' : common_deps,
        },
]
