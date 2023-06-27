# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_NSS_MYHOSTNAME') != 1
        subdir_done()
endif

modules += [
        nss_template + {
                'name' : 'nss_myhostname',
                'sources' : files('nss-myhostname.c'),
                'link_depends' : files('nss-myhostname.sym'),
        },
]
