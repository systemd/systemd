# SPDX-License-Identifier: LGPL-2.1-or-later

systemd_sysupdated_sources = files(
        'sysupdated.c',
)

systemd_sysupdate_sources = files(
        'sysupdate-cache.c',
        'sysupdate-cache.h',
        'sysupdate-instance.c',
        'sysupdate-instance.h',
        'sysupdate-partition.c',
        'sysupdate-partition.h',
        'sysupdate-pattern.c',
        'sysupdate-pattern.h',
        'sysupdate-resource.c',
        'sysupdate-resource.h',
        'sysupdate-transfer.c',
        'sysupdate-transfer.h',
        'sysupdate-update-set.c',
        'sysupdate-update-set.h',
        'sysupdate.c',
        'sysupdate.h',
)

if conf.get('ENABLE_SYSUPDATE') == 1
        install_data('org.freedesktop.sysupdate1.conf',
                     install_dir : dbuspolicydir)
        install_data('org.freedesktop.sysupdate1.service',
                     install_dir : dbussystemservicedir)
        install_data('org.freedesktop.sysupdate1.policy',
                     install_dir : polkitpolicydir)
endif
