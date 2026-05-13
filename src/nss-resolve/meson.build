# SPDX-License-Identifier: LGPL-2.1-or-later

modules += [
        nss_template + {
                'name' : 'nss_resolve',
                'conditions' : ['ENABLE_NSS_RESOLVE'],
                'sources' : files('nss-resolve.c'),
                'version-script' : meson.current_source_dir() / 'nss-resolve.sym',
                'include_directories' : includes +
                                        include_directories('../resolve'),
        },
]
