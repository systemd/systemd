# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_NSS_SYSTEMD') != 1
        subdir_done()
endif

sources = files(
        'nss-systemd.c',
        'userdb-glue.c',
)

modules += [[
        {
                'name' : 'nss_systemd',
        },
        nss_template + {
                'sources' : sources,
                'link_depends' : files('nss-systemd.sym'),
        },
]]
