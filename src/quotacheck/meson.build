# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_QUOTACHECK') != 1
        subdir_done()
endif

executables += [
        libexec_template + {
                'name' : 'systemd-quotacheck',
                'sources' : files('quotacheck.c'),
        },
]
