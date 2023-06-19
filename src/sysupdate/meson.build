# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_SYSUPDATE') != 1
        subdir_done()
endif

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
        'sysupdate-util.c',
        'sysupdate-util.h',
        'sysupdate.c',
        'sysupdate.h',
)

executables += [[
        {
                'name' : 'systemd-sysupdate',
                'public' : true,
        },
        daemon_template + {
                'sources' : systemd_sysupdate_sources,
                'link_with' : [libshared,
                               libshared_fdisk],
                'dependencies' : [libblkid,
                                  libfdisk,
                                  libopenssl,
                                  threads,
                                  userspace,
                                  versiondep],
        },
]]
