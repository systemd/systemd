# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('HAVE_LIBDEVMAPPER') != 1
        subdir_done()
endif

systemd_dmclone_sources = files(
        'dmclone.c',
)

executables += [
        executable_template + {
                'name' : 'systemd-dmclone',
                'public' : true,
                'sources' : systemd_dmclone_sources,
                'dependencies' : [
                        libdevmapper,
                ],
        },
]
