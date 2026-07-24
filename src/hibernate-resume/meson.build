# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_HIBERNATE') != 1
        subdir_done()
endif

executables += [
        libexec_template + {
                'name' : 'systemd-hibernate-resume',
                'sources' : files('hibernate-resume.c'),
                'export' : files('hibernate-resume-config.c'),
        },
        generator_template + {
                'name' : 'systemd-hibernate-resume-generator',
                'sources' : files('hibernate-resume-generator.c'),
                'import' : ['systemd-hibernate-resume'],
                'dependencies' : [tpm2_cflags, libopenssl_cflags],
        },
]
