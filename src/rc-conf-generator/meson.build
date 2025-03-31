# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-rc-conf-generator',
                'sources' : files('rc-conf-generator.c'),
                'dependencies' : [libgo_dep],
        },
]

install_data('rc.conf',
             install_dir : pkgdatadir / 'rc-conf-generator')
