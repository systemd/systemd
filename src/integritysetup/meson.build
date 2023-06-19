# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('HAVE_LIBCRYPTSETUP') != 1
        subdir_done()
endif

executables += [
        [
                {
                        'name' : 'systemd-integritysetup',
                },
                daemon_template + {
                        'sources' : files('integritysetup.c',
                                          'integrity-util.c'),
                        'dependencies' : [libcryptsetup,
                                          userspace,
                                          versiondep],
                },
        ],
        [
                {
                        'name' : 'systemd-integritysetup-generator',
                },
                generator_template + {
                        'sources' : files('integritysetup-generator.c',
                                          'integrity-util.c'),
                },
        ],
]
