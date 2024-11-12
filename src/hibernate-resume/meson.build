# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_HIBERNATE') != 1
        subdir_done()
endif

executables += [
        generator_template + {
                'name' : 'systemd-hibernate-resume-generator',
                'sources' : files(
                        'hibernate-resume-generator.c',
                        'hibernate-resume-config.c',
                ),
        },
        libexec_template + {
                'name' : 'systemd-hibernate-resume',
                'sources' : files(
                        'hibernate-resume.c',
                        'hibernate-resume-config.c',
                ),
        },
]
