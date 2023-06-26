# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_NSS_MYMACHINES') != 1
        subdir_done()
endif

modules += [
        nss_template + {
                'name' : 'nss_mymachines',
                'sources' : files('nss-mymachines.c'),
                'link_depends' : files('nss-mymachines.sym'),
        },
]
