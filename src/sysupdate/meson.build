# SPDX-License-Identifier: LGPL-2.1-or-later

systemd_sysupdate_sources = files(
        'sysupdate-cache.c',
        'sysupdate-feature.c',
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

systemd_updatectl_sources = files(
        'sysupdate-update-set-flags.c',
        'sysupdate-util.c',
        'updatectl.c',
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
        libexec_template + {
                'name' : 'systemd-sysupdated',
                'dbus' : true,
                'conditions' : ['ENABLE_SYSUPDATED'],
                'sources' : files('sysupdated.c'),
                'dependencies' : threads,
        },
        executable_template + {
                'name' : 'updatectl',
                'public' : true,
                'sources' : systemd_updatectl_sources,
                'conditions' : ['ENABLE_SYSUPDATED'],
        },
]

if conf.get('ENABLE_SYSUPDATED') == 1
        install_data('org.freedesktop.sysupdate1.conf',
                     install_dir : dbuspolicydir)
        install_data('org.freedesktop.sysupdate1.service',
                     install_dir : dbussystemservicedir)
        install_data('org.freedesktop.sysupdate1.policy',
                     install_dir : polkitpolicydir)
endif
