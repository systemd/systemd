# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-executor',
                'public' : true,
                'sources' : files('executor.c'),
                'include_directories' : core_includes,
                'link_with' : [
                        libcore,
                        libshared,
                ],
                'dependencies' : [
                        libapparmor,
                        libpam,
                        libseccomp,
                        libselinux,
                ],
        },
]
