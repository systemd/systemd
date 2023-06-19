# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_HIBERNATE') != 1
        subdir_done()
endif

executables += [
        [
                {
                        'name' : 'systemd-hibernate-resume-generator',
                },
                generator_template + {
                        'sources' : files('hibernate-resume-generator.c'),
                },
        ],
        [
                {
                        'name' : 'systemd-hibernate-resume',
                },
                daemon_template + {
                        'sources' : files('hibernate-resume.c'),
                },
        ],
]
