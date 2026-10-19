# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('HAVE_LIBCRYPTSETUP') != 1
        subdir_done()
endif

executables += [
        libexec_template + {
                'name' : 'systemd-integritysetup',
                'sources' : files('integritysetup.c'),
                'export' : files('integrity-util.c'),
                'dependencies' : libcryptsetup_cflags,
        },
        generator_template + {
                'name' : 'systemd-integritysetup-generator',
                'sources' : files('integritysetup-generator.c'),
                'import' : ['systemd-integritysetup'],
        },
]
