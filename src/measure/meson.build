# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-measure',
                'conditions' : ['ENABLE_MEASURE'],
                'sources' : files('measure-tool.c'),
                'dependencies' : [
                        libopenssl_cflags,
                        tpm2_cflags,
                ],
        },
]
