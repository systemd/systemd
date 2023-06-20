# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('HAVE_LIBCRYPTSETUP') != 1
        subdir_done()
endif

executables += [
        daemon_template + {
                'name' : 'systemd-integritysetup',
                'sources' : files('integritysetup.c',
                                  'integrity-util.c'),
                'dependencies' : [libcryptsetup,
                                  userspace,
                                  versiondep],
        },
        generator_template + {
                'name' : 'systemd-integritysetup-generator',
                'sources' : files('integritysetup-generator.c',
                                  'integrity-util.c'),
        },
]
