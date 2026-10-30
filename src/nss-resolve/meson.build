# SPDX-License-Identifier: LGPL-2.1-or-later

modules += [
        nss_template + {
                'name' : 'nss_resolve',
                'conditions' : ['ENABLE_NSS_RESOLVE'],
                'sources' : files('nss-resolve.c'),
                'version-script' : 'src/nss-resolve/nss-resolve.sym',
                'include_directories' : [include_directories('../resolve'),
                                         includes],
        },
]
