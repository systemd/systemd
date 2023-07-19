# SPDX-License-Identifier: LGPL-2.1-or-later

systemd_sysupdate_sources = files(
        'sysupdate-cache.c',
        'sysupdate-instance.c',
        'sysupdate-partition.c',
        'sysupdate-pattern.c',
        'sysupdate-resource.c',
        'sysupdate-transfer.c',
        'sysupdate-update-set.c',
        'sysupdate-update-set-flags.c',
        'sysupdate-util.c',
        'sysupdate.c',
)

executables += [
        libexec_template + {
                'name' : 'systemd-sysupdate',
                'public' : true,
                'conditions' : ['ENABLE_SYSUPDATE'],
                'sources' : systemd_sysupdate_sources,
                'link_with' : [
                        libshared,
                        libshared_fdisk,
                ],
                'dependencies' : [
                        libblkid,
                        libfdisk,
                        libopenssl,
                        threads,
                ],
        },
]
