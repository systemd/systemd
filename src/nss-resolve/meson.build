# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_NSS_RESOLVE') != 1
        subdir_done()
endif

modules += [
        nss_template + {
                'name' : 'nss_resolve',
                'sources' : files('nss-resolve.c'),
                'link_depends' : files('nss-resolve.sym'),
                'include_directories' : includes +
                                        include_directories('../resolve'),
        },
]
