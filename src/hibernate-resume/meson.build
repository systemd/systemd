# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        generator_template + {
                'name' : 'systemd-hibernate-resume-generator',
                'conditions' : ['ENABLE_HIBERNATE'],
                'sources' : files(
                        'hibernate-resume-generator.c',
                        'hibernate-resume-config.c',
                ),
        },
        libexec_template + {
                'name' : 'systemd-hibernate-resume',
                'conditions' : ['ENABLE_HIBERNATE'],
                'sources' : files(
                        'hibernate-resume.c',
                        'hibernate-resume-config.c',
                ),
        },
]
