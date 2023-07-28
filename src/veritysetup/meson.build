# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('HAVE_LIBCRYPTSETUP') != 1
        subdir_done()
endif

executables += [
        libexec_template + {
                'name' : 'systemd-veritysetup',
                'sources' : files('veritysetup.c'),
                'dependencies' : libcryptsetup,
        },
        generator_template + {
                'name' : 'systemd-veritysetup-generator',
                'sources' : files('veritysetup-generator.c'),
        },
]
