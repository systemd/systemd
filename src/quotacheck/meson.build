# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-quotacheck',
                'conditions' : ['ENABLE_QUOTACHECK'],
                'sources' : files('quotacheck.c'),
        },
]
