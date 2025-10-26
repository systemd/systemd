# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('HAVE_LIBCRYPTSETUP') != 1
        subdir_done()
endif

executables += [
        libexec_template + {
                'name' : 'systemd-integritysetup',
                'sources' : files(
                        'integrity-util.c',
                        'integritysetup.c',
                ),
                'extract' : files('integrity-util.c'),
                'dependencies' : libcryptsetup_cflags,
        },
        generator_template + {
                'name' : 'systemd-integritysetup-generator',
                'sources' : files('integritysetup-generator.c'),
                'objects' : ['systemd-integritysetup'],
        },
]
