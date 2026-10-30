# SPDX-License-Identifier: LGPL-2.1-or-later

modules += [
        nss_template + {
                'name' : 'nss_myhostname',
                'conditions' : ['ENABLE_NSS_MYHOSTNAME'],
                'sources' : files('nss-myhostname.c'),
                'version-script' : 'src/nss-myhostname/nss-myhostname.sym',
        },
]
