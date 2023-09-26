# SPDX-License-Identifier: LGPL-2.1-or-later

modules += [
        nss_template + {
                'name' : 'nss_mymachines',
                'conditions' : ['ENABLE_NSS_MYMACHINES'],
                'sources' : files('nss-mymachines.c'),
                'version-script' : meson.current_source_dir() / 'nss-mymachines.sym',
        },
]
