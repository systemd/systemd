# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-integritysetup',
                'conditions' : ['HAVE_LIBCRYPTSETUP'],
                'sources' : files(
                        'integrity-util.c',
                        'integritysetup.c',
                ),
                'dependencies' : libcryptsetup,
        },
        generator_template + {
                'name' : 'systemd-integritysetup-generator',
                'conditions' : ['HAVE_LIBCRYPTSETUP'],
                'sources' : files(
                        'integrity-util.c',
                        'integritysetup-generator.c',
                ),
        },
]
