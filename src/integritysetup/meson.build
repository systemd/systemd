# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-integritysetup',
                'conditions' : ['HAVE_LIBCRYPTSETUP'],
                'sources' : files('integritysetup.c',
                                  'integrity-util.c'),
                'dependencies' : [libcryptsetup,
                                  versiondep],
        },
        generator_template + {
                'name' : 'systemd-integritysetup-generator',
                'conditions' : ['HAVE_LIBCRYPTSETUP'],
                'sources' : files('integritysetup-generator.c',
                                  'integrity-util.c'),
        },
]
