# SPDX-License-Identifier: LGPL-2.1-or-later

systemd_mountwork_sources = files(
        'mountwork.c',
)

systemd_mountfsd_sources = files(
        'mountfsd.c',
        'mountfsd-manager.c',
)

executables += [
        libexec_template + {
                'name' : 'systemd-mountfsd',
                'conditions' : ['ENABLE_MOUNTFSD'],
                'sources' : systemd_mountfsd_sources,
        },
        libexec_template + {
                'name' : 'systemd-mountwork',
                'conditions' : ['ENABLE_MOUNTFSD'],
                'sources' : systemd_mountwork_sources,
        },
]

install_data('io.systemd.mount-file-system.policy',
             install_dir : polkitpolicydir)
