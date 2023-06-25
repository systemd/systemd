# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-veritysetup',
                'conditions' : ['HAVE_LIBCRYPTSETUP'],
                'sources' : files('veritysetup.c'),
                'dependencies' : libcryptsetup,
        },
        generator_template + {
                'name' : 'systemd-veritysetup-generator',
                'conditions' : ['HAVE_LIBCRYPTSETUP'],
                'sources' : files('veritysetup-generator.c'),
        },
]
